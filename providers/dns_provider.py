"""
dns_provider.py — DNS Intelligence Provider

Fontes integradas:
  1. dnspython          — resolução direta (A, MX, NS, TXT, CNAME)
  2. HackerTarget       — reverse IP lookup (neighbor domains)
  3. crt.sh             — Certificate Transparency (subdomínios via SSL logs)

O valor central aqui é o pivotamento:
  domínio → IP → quais outros domínios apontam para este IP (neighbor domains)
  Isso revela infraestrutura compartilhada que o DNS direto nunca entrega.

Dependências:
  pip install dnspython requests
"""

from __future__ import annotations

import logging
import time
from typing import Any

import dns.resolver
import dns.exception
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from providers.base import NormalizedEntity, ProviderResult

logger = logging.getLogger(__name__)

TIMEOUT = 10

_session = requests.Session()
_session.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
    ),
)

# ── DNS direto (dnspython) ────────────────────────────────────────────────────

_RECORD_TYPES = ["A", "MX", "NS", "TXT", "CNAME"]


def _resolve_all(domain: str) -> dict[str, list[str]]:
    """
    Resolve todos os tipos de registro relevantes para um domínio.
    Falhas por tipo são silenciosas — retorna o que conseguir.
    """
    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8.0  # timeout global por consulta

    for rtype in _RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except dns.exception.DNSException as e:
            logger.debug("DNS %s para %s falhou: %s", rtype, domain, e)
            results[rtype] = []

    return results


def _normalize_dns(records: dict[str, list[str]], domain: str) -> list[NormalizedEntity]:
    """
    Cada tipo de registro vira uma entidade separada.
    Registros vazios são ignorados — sem ruído no grafo.
    """
    entities: list[NormalizedEntity] = []

    for rtype, values in records.items():
        if not values:
            continue
        entities.append(NormalizedEntity(
            entity=domain,
            source="dnspython",
            data_type=f"dns_{rtype.lower()}",
            value=",".join(values),
            metadata={
                "record_type": rtype,
                "count": len(values),
                "records": values,
            },
            confidence=0.95,
        ))

    return entities


# ── HackerTarget — Reverse IP ─────────────────────────────────────────────────

def _fetch_reverse_ip(ip: str) -> list[str]:
    """
    Dado um IP, retorna todos os domínios que apontam para ele.
    HackerTarget free: ~100 req/dia sem key.

    Retorna lista de domínios ou [] em falha.
    """
    url = "https://api.hackertarget.com/reverseiplookup/"
    try:
        resp = _session.get(url, params={"q": ip}, timeout=TIMEOUT)
        resp.raise_for_status()
        text = resp.text.strip()

        # Respostas de erro da API chegam como texto simples
        if "error" in text.lower() or "no records" in text.lower():
            logger.info("HackerTarget: sem neighbor domains para %s", ip)
            return []

        domains = [line.strip() for line in text.splitlines() if line.strip()]
        logger.info("HackerTarget: %d neighbor domains encontrados para %s", len(domains), ip)
        return domains

    except requests.exceptions.RequestException as e:
        logger.warning("HackerTarget falhou para %s: %s", ip, e)
        return []


def _normalize_reverse_ip(
    domains: list[str], ip: str, origin_domain: str
) -> list[NormalizedEntity]:
    """
    Neighbor domains → NormalizedEntity por domínio.

    Por que uma entidade por domínio (não lista agregada):
    O grafo precisa criar nós individuais para cada neighbor domain
    e computar a aresta "compartilha_ip_com". Se fosse lista,
    seria dado morto para correlação.
    """
    entities: list[NormalizedEntity] = []

    for neighbor in domains:
        # Ignora o próprio domínio de origem
        if neighbor == origin_domain:
            continue

        entities.append(NormalizedEntity(
            entity=ip,
            source="hackertarget_reverseip",
            data_type="neighbor_domain",
            value=neighbor,
            metadata={
                "shared_ip": ip,
                "discovered_from": origin_domain,
                "pivot": "reverse_ip",
            },
            confidence=0.82,
        ))

    return entities


# ── crt.sh — Certificate Transparency ────────────────────────────────────────

def _fetch_crtsh(domain: str) -> list[str]:
    """
    crt.sh: subdomínios via logs de CT (Certificate Transparency).
    Sem autenticação. Sem rate limit documentado.

    Retorna lista de subdomínios únicos (sem wildcards).
    """
    url = "https://crt.sh/"
    try:
        resp = _session.get(
            url,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        subdomains: set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            # Remove wildcards e quebra SANs múltiplos (separados por \n)
            for sub in name.splitlines():
                sub = sub.strip().lstrip("*.")
                if sub and sub.endswith(domain) and sub != domain:
                    subdomains.add(sub.lower())

        return sorted(subdomains)

    except requests.exceptions.RequestException as e:
        logger.warning("crt.sh falhou para %s: %s", domain, e)
        return []
    except (ValueError, KeyError) as e:
        logger.warning("crt.sh parse error para %s: %s", domain, e)
        return []


def _normalize_crtsh(subdomains: list[str], domain: str) -> list[NormalizedEntity]:
    """Subdomínios do CT log → NormalizedEntity por subdomínio."""
    entities: list[NormalizedEntity] = []

    for sub in subdomains:
        entities.append(NormalizedEntity(
            entity=domain,
            source="crtsh",
            data_type="subdomain",
            value=sub,
            metadata={
                "parent_domain": domain,
                "discovery_method": "certificate_transparency",
            },
            confidence=0.88,
        ))

    return entities


# ── Entry point público ───────────────────────────────────────────────────────

def query_dns(domain: str, resolved_ip: str | None = None) -> ProviderResult:
    """
    Pipeline DNS completo para um domínio.

    Fluxo:
      domínio → DNS (A/MX/NS/TXT/CNAME)
              → crt.sh (subdomínios via CT)
              → IP do A record → HackerTarget (neighbor domains)

    Args:
        domain:      Domínio alvo (ex: "empresa.com.br").
        resolved_ip: IP já resolvido por agente upstream (evita nova resolução).
                     Se None, extrai do registro A.

    Returns:
        ProviderResult com entidades DNS, subdomínios e neighbor domains.
    """
    entities: list[NormalizedEntity] = []
    errors:   list[str]              = []
    metadata: dict[str, Any]         = {
        "domain": domain,
        "ip_resolved": "",
        "subdomains_found": 0,
        "neighbor_domains": 0,
        "dns_records": {},
    }

    # ── 1. Resolução DNS direta ───────────────────────────────────────────────
    try:
        records = _resolve_all(domain)
        dns_entities = _normalize_dns(records, domain)
        entities.extend(dns_entities)
        metadata["dns_records"] = {k: v for k, v in records.items() if v}

        # Extrai IP do registro A para o pivot de reverse IP
        if not resolved_ip and records.get("A"):
            resolved_ip = records["A"][0]
            metadata["ip_resolved"] = resolved_ip

    except Exception as e:
        errors.append(f"dns_resolution: {e}")

    # ── 2. crt.sh — subdomínios via CT ───────────────────────────────────────
    try:
        # Pequeno delay para não sobrecarregar crt.sh
        time.sleep(0.5)
        subdomains = _fetch_crtsh(domain)
        ct_entities = _normalize_crtsh(subdomains, domain)
        entities.extend(ct_entities)
        metadata["subdomains_found"] = len(subdomains)
    except Exception as e:
        errors.append(f"crtsh: {e}")

    # ── 3. HackerTarget — neighbor domains via reverse IP ────────────────────
    if resolved_ip:
        try:
            neighbors = _fetch_reverse_ip(resolved_ip)
            neighbor_entities = _normalize_reverse_ip(neighbors, resolved_ip, domain)
            entities.extend(neighbor_entities)
            metadata["neighbor_domains"] = len(neighbor_entities)
        except Exception as e:
            errors.append(f"hackertarget: {e}")
    else:
        logger.info("dns_provider: IP não disponível — neighbor domains ignorados para %s", domain)

    return ProviderResult(
        provider="dns_provider",
        target=domain,
        entities=entities,
        errors=errors,
        metadata=metadata,
    )