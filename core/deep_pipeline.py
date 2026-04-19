"""
core/deep_pipeline.py — Modo Deep Intelligence

Pipeline expandido que roda APÓS o pipeline padrão.
Ativado via --deep na CLI. Zero impacto no fluxo padrão.

Fluxo:
  args (target + cnpj opcional)
    ├── cnpj_provider   → empresa + sócios
    ├── gov_provider    → contratos + sanções
    ├── infra_provider  → portas + ASN + CIDR
    ├── dns_provider    → DNS + subdomínios + neighbor domains
    ├── reputation_provider → AbuseIPDB + VirusTotal + Censys
    └── SentinelGraph   → grafo + risk score + correlações
                              ↓
                         ai_analyst (contexto adicional)
                              ↓
                         intel_reporter (relatório enriquecido)
                              ↓
                         core/database.py (indexação)

Nenhum agente existente é alterado.
"""

from __future__ import annotations

import json
import logging
import socket
from argparse import Namespace
from datetime import datetime
from pathlib import Path
from typing import Any

from providers.base import ProviderResult
from providers.cnpj_provider import query_cnpj
from providers.gov_provider import query_gov
from providers.infra_provider import query_infra
from providers.dns_provider import query_dns
from providers.reputation_provider import query_reputation
from core.graph import SentinelGraph

logger = logging.getLogger(__name__)

# Diretório de output — mesmo padrão do pipeline padrão
DATA_DIR    = Path("data")
REPORTS_DIR = Path("reports")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_domain_to_ip(domain: str) -> str | None:
    """
    Resolve domínio para IP antes de chamar infra_provider e reputation_provider.
    Usa socket para não criar dependência de dnspython aqui — dns_provider já faz isso.
    Retorna None se resolução falhar.
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        logger.warning("Não foi possível resolver %s: %s", domain, e)
        return None


def _is_ip(value: str) -> bool:
    """Detecta se o target é IP ou domínio/CNPJ."""
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _extract_telefone(cnpj_result: ProviderResult | None) -> str | None:
    """
    Extrai telefone comercial do resultado do cnpj_provider
    para repassar ao gov_provider.
    """
    if not cnpj_result:
        return None
    for entity in cnpj_result.entities:
        if entity.data_type == "telefone_comercial":
            return entity.value
    return None


def _save_deep_output(target: str, graph_dict: dict, metadata: dict) -> Path:
    """
    Salva output do deep mode em data/deep_{target}_{timestamp}.json.
    Segue o mesmo padrão de nomeação do pipeline padrão.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    path = DATA_DIR / f"deep_{safe_target}_{timestamp}.json"

    output = {
        "target":    target,
        "timestamp": timestamp,
        "metadata":  metadata,
        "graph":     graph_dict,
    }

    with path.open("w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, default=str)

    logger.info("Deep output salvo em %s", path)
    return path


# ── Coleta por provider ───────────────────────────────────────────────────────

def _run_cnpj(cnpj: str) -> ProviderResult | None:
    """Executa cnpj_provider com log de resultado."""
    if not cnpj:
        return None
    logger.info("[deep] cnpj_provider → %s", cnpj)
    try:
        result = query_cnpj(cnpj)
        logger.info(
            "[deep] cnpj_provider: %d entidades, %d erros",
            len(result.entities), len(result.errors),
        )
        return result
    except Exception as e:
        logger.error("[deep] cnpj_provider falhou: %s", e)
        return None


def _run_gov(cnpj: str, telefone: str | None) -> ProviderResult | None:
    """Executa gov_provider. Requer CNPJ — ignora silenciosamente se ausente."""
    if not cnpj:
        logger.info("[deep] gov_provider ignorado — CNPJ não fornecido")
        return None
    logger.info("[deep] gov_provider → %s", cnpj)
    try:
        result = query_gov(cnpj, telefone_publico=telefone)
        logger.info(
            "[deep] gov_provider: %d contratos, %d sanções CEIS, %d sanções CNEP",
            result.metadata.get("contratos_encontrados", 0),
            result.metadata.get("sancoes_ceis", 0),
            result.metadata.get("sancoes_cnep", 0),
        )
        return result
    except Exception as e:
        logger.error("[deep] gov_provider falhou: %s", e)
        return None


def _run_infra(ip: str) -> ProviderResult | None:
    """Executa infra_provider. Requer IP público válido."""
    if not ip:
        return None
    logger.info("[deep] infra_provider → %s", ip)
    try:
        result = query_infra(ip)
        logger.info(
            "[deep] infra_provider: %d portas, %d CVEs, ASN=%s, %d blocos CIDR",
            result.metadata.get("shodan_ports", 0),
            result.metadata.get("cves_found", 0),
            result.metadata.get("asn", "N/A"),
            result.metadata.get("cidr_blocks", 0),
        )
        return result
    except Exception as e:
        logger.error("[deep] infra_provider falhou: %s", e)
        return None


def _run_dns(domain: str, resolved_ip: str | None) -> ProviderResult | None:
    """Executa dns_provider. Ignorado se target for IP direto."""
    if not domain:
        return None
    logger.info("[deep] dns_provider → %s", domain)
    try:
        result = query_dns(domain, resolved_ip=resolved_ip)
        logger.info(
            "[deep] dns_provider: %d subdomínios, %d neighbor domains",
            result.metadata.get("subdomains_found", 0),
            result.metadata.get("neighbor_domains", 0),
        )
        return result
    except Exception as e:
        logger.error("[deep] dns_provider falhou: %s", e)
        return None


def _run_reputation(target: str, target_type: str) -> ProviderResult | None:
    """Executa reputation_provider para IP ou domínio."""
    logger.info("[deep] reputation_provider → %s (%s)", target, target_type)
    try:
        result = query_reputation(target, target_type=target_type)
        logger.info(
            "[deep] reputation_provider: abuse=%s, vt_detections=%s, censys=%s",
            result.metadata.get("abuse_score", "N/A"),
            result.metadata.get("vt_detections", "N/A"),
            "✓" if result.metadata.get("censys_called") else "ignorado",
        )
        return result
    except Exception as e:
        logger.error("[deep] reputation_provider falhou: %s", e)
        return None


# ── Entry point principal ─────────────────────────────────────────────────────

def run_deep(args: Namespace) -> dict[str, Any]:
    """
    Executa o pipeline deep completo.

    Args:
        args: Namespace com atributos:
              - args.target : domínio ou IP alvo (obrigatório)
              - args.cnpj   : CNPJ da empresa (opcional)

    Returns:
        Dict com graph_result + metadata de execução.
        Pode ser passado diretamente ao ai_analyst como contexto adicional.
    """
    target: str = args.target
    cnpj:   str = getattr(args, "cnpj", "") or ""

    logger.info("=" * 60)
    logger.info("[deep] Iniciando deep pipeline para: %s", target)
    if cnpj:
        logger.info("[deep] CNPJ fornecido: %s", cnpj)
    logger.info("=" * 60)

    # ── Detecta tipo de target e resolve IP ──────────────────────────────────
    target_is_ip = _is_ip(target)
    domain       = None if target_is_ip else target
    ip           = target if target_is_ip else _resolve_domain_to_ip(target)

    logger.info(
        "[deep] Target: %s | IP resolvido: %s",
        "IP direto" if target_is_ip else f"domínio ({domain})",
        ip or "falhou",
    )

    # ── Executa providers em sequência ───────────────────────────────────────
    # Sequência importa: cnpj → gov (usa telefone do cnpj)
    #                    dns → infra (dns resolve o IP para o infra)
    # Providers independentes poderiam ser paralelos (asyncio — Fase 3)

    results: list[ProviderResult] = []

    # 1. CNPJ
    cnpj_result = _run_cnpj(cnpj)
    if cnpj_result:
        results.append(cnpj_result)

    # 2. Gov (usa telefone retornado pelo CNPJ)
    telefone = _extract_telefone(cnpj_result)
    gov_result = _run_gov(cnpj, telefone)
    if gov_result:
        results.append(gov_result)

    # 3. DNS (apenas para domínios)
    dns_result = _run_dns(domain, resolved_ip=ip)
    if dns_result:
        results.append(dns_result)
        # Atualiza IP se dns_provider resolveu e não tínhamos
        if not ip and dns_result.metadata.get("ip_resolved"):
            ip = dns_result.metadata["ip_resolved"]
            logger.info("[deep] IP atualizado via dns_provider: %s", ip)

    # 4. Infra (IP obrigatório)
    infra_result = _run_infra(ip)
    if infra_result:
        results.append(infra_result)

    # 5. Reputação
    rep_target      = ip if ip else target
    rep_target_type = "ip" if ip else "domain"
    rep_result = _run_reputation(rep_target, rep_target_type)
    if rep_result:
        results.append(rep_result)

    # ── Constrói e computa o grafo ────────────────────────────────────────────
    logger.info("[deep] Construindo grafo de inteligência...")
    graph = SentinelGraph()
    graph.ingest(results)
    graph_result = graph.compute(risk_threshold=30.0)

    # ── Monta metadata de execução ────────────────────────────────────────────
    providers_executados = [r.provider for r in results]
    providers_com_erro   = [r.provider for r in results if r.errors]

    metadata = {
        "target":               target,
        "cnpj":                 cnpj or None,
        "ip_resolvido":         ip,
        "providers_executados": providers_executados,
        "providers_com_erro":   providers_com_erro,
        "timestamp":            datetime.now().isoformat(),
        "risk_summary":         graph_result.risk_summary,
        "stats":                graph_result.stats,
    }

    # ── Salva output em disco ─────────────────────────────────────────────────
    graph_dict  = graph_result.to_dict()
    output_path = _save_deep_output(target, graph_dict, metadata)
    metadata["output_path"] = str(output_path)

    # ── Log de encerramento ───────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("[deep] Pipeline concluído")
    logger.info(
        "[deep] Nós: %d | Arestas: %d | High risk: %d | Risk total: %.1f",
        graph_result.stats["total_nodes"],
        graph_result.stats["total_edges"],
        graph_result.stats["high_risk_nodes"],
        graph_result.risk_summary["total_risk_score"],
    )
    if graph_result.risk_summary.get("has_sanctioned_entity"):
        logger.warning("[deep] ⚠️  EMPRESA CONSTA NO CEIS/CNEP")
    logger.info("[deep] Output: %s", output_path)
    logger.info("=" * 60)

    return {
        "graph":    graph_dict,
        "metadata": metadata,
    }