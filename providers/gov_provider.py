"""
gov_provider.py — Portal da Transparência Intelligence Provider

Endpoints cobertos:
  - Contratos públicos (por CNPJ do fornecedor)
  - CEIS (Cadastro de Empresas Inidôneas e Suspensas)
  - CNEP (Cadastro Nacional de Empresas Punidas)
  - Telefone público derivado do CNPJ (via cnpj_provider normalizado)

Fonte: api.portaldatransparencia.gov.br
Auth: API key via header 'chave-api-dados' (gratuita em portaldatransparencia.gov.br/api)
Rate limit: 500 req/hora no plano gratuito.

NÃO busca telefone pessoal de sócios — apenas contato comercial público do CNPJ.
Escopo: LGPD art. 7º, inciso II (dado manifestamente público).
"""

from __future__ import annotations

import os
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from providers.base import NormalizedEntity, ProviderResult, safe_query

logger = logging.getLogger(__name__)

# ── Configuração ────────────────────────────────────────────────────────────

BASE_URL = "https://api.portaldatransparencia.gov.br/api-de-dados"
API_KEY  = os.getenv("TRANSPARENCIA_API_KEY", "")

HEADERS = {
    "chave-api-dados": API_KEY,
    "Accept": "application/json",
}

# Session com retry automático em 429 / 5xx
_session = requests.Session()
_adapter = HTTPAdapter(
    max_retries=Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
)
_session.mount("https://", _adapter)

TIMEOUT = 15  # segundos por requisição


# ── Helpers internos ─────────────────────────────────────────────────────────

def _get(endpoint: str, params: dict[str, Any]) -> list[dict] | None:
    """
    GET genérico com tratamento de erros.
    Retorna lista de dicts ou None em falha.
    """
    if not API_KEY:
        logger.warning("TRANSPARENCIA_API_KEY não configurada — gov_provider limitado")
        return None

    url = f"{BASE_URL}/{endpoint}"
    try:
        resp = _session.get(url, headers=HEADERS, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else [data]
    except requests.exceptions.HTTPError as e:
        logger.error("HTTP %s em %s: %s", e.response.status_code, endpoint, e)
        return None
    except requests.exceptions.RequestException as e:
        logger.error("Erro de rede em %s: %s", endpoint, e)
        return None


def _strip_cnpj(cnpj: str) -> str:
    """Remove máscara: '12.345.678/0001-99' → '12345678000199'."""
    return "".join(c for c in cnpj if c.isdigit())


# ── Funções de coleta ────────────────────────────────────────────────────────

def fetch_contratos(cnpj: str, pagina: int = 1) -> list[dict]:
    """
    Contratos onde a empresa é fornecedora.
    Endpoint: /contratos?cnpjFornecedor=&pagina=
    """
    raw = _get("contratos", {"cnpjFornecedor": _strip_cnpj(cnpj), "pagina": pagina})
    return raw or []


def fetch_ceis(cnpj: str) -> list[dict]:
    """
    Cadastro de Empresas Inidôneas e Suspensas.
    Retorna lista vazia se empresa não constar.
    """
    raw = _get("ceis", {"cnpjSancionado": _strip_cnpj(cnpj)})
    return raw or []


def fetch_cnep(cnpj: str) -> list[dict]:
    """
    Cadastro Nacional de Empresas Punidas.
    """
    raw = _get("cnep", {"cnpjSancionado": _strip_cnpj(cnpj)})
    return raw or []


# ── Normalizadores ───────────────────────────────────────────────────────────

def _normalize_contrato(raw: dict, cnpj: str) -> NormalizedEntity:
    """Contrato público → NormalizedEntity."""
    numero     = raw.get("numero") or raw.get("id") or "desconhecido"
    orgao      = raw.get("unidadeGestora", {}).get("orgaoVinculado", {}).get("nome", "")
    valor      = raw.get("valorInicial") or raw.get("valor") or 0
    vigencia   = raw.get("dataFimVigencia") or raw.get("dataFim") or ""
    objeto     = raw.get("objeto") or raw.get("descricaoObjeto") or ""

    return NormalizedEntity(
        entity=cnpj,
        source="portal_transparencia",
        data_type="contrato_publico",
        value=numero,
        metadata={
            "orgao": orgao,
            "valor_brl": valor,
            "vigencia": vigencia,
            "objeto": objeto[:300],          # trunca objeto muito longo
            "modalidade": raw.get("modalidadeLicitacao", {}).get("descricao", ""),
        },
        confidence=0.95,
    )


def _normalize_sancao(raw: dict, cnpj: str, tipo: str) -> NormalizedEntity:
    """Sanção CEIS ou CNEP → NormalizedEntity."""
    return NormalizedEntity(
        entity=cnpj,
        source="portal_transparencia",
        data_type=tipo,                      # "sancao_ceis" ou "sancao_cnep"
        value=raw.get("numeroProcesso") or raw.get("id") or "s/n",
        metadata={
            "motivo":         raw.get("fundamentacaoLegal") or raw.get("tipoSancao", {}).get("descricao", ""),
            "orgao_sancao":   raw.get("orgaoSancionador", {}).get("nome", ""),
            "data_inicio":    raw.get("dataInicioSancao") or raw.get("dataPublicacao") or "",
            "data_fim":       raw.get("dataFimSancao") or "",
            "abrangencia":    raw.get("abrangenciaDecisaoJudicial") or "",
        },
        confidence=0.98,  # dado oficial — alta confiança
    )


def _normalize_telefone_publico(telefone: str, cnpj: str) -> NormalizedEntity:
    """
    Telefone comercial público do CNPJ → NormalizedEntity.
    Origem: dado da Receita Federal via cnpj_provider, repassado aqui.
    NÃO é telefone pessoal de sócio.
    """
    return NormalizedEntity(
        entity=cnpj,
        source="receita_federal_via_cnpj",
        data_type="telefone_comercial",
        value=telefone,
        metadata={
            "nota": "Contato comercial público — Receita Federal",
            "lgpd_base": "dado manifestamente público (art. 7º, II)",
        },
        confidence=0.80,
    )


# ── Entry point público ──────────────────────────────────────────────────────

def query_gov(cnpj: str, telefone_publico: str | None = None) -> ProviderResult:
    """
    Pipeline completo do gov_provider para um CNPJ.

    Args:
        cnpj:             CNPJ com ou sem máscara.
        telefone_publico: Telefone comercial retornado pelo cnpj_provider (opcional).

    Returns:
        ProviderResult com entities, errors e metadata de execução.
    """
    entities: list[NormalizedEntity] = []
    errors:   list[str]              = []
    metadata: dict[str, Any]         = {
        "cnpj": _strip_cnpj(cnpj),
        "contratos_encontrados": 0,
        "sancoes_ceis": 0,
        "sancoes_cnep": 0,
            "tem_sancao_ativa": False,
    }

    # ── Contratos ────────────────────────────────────────────────────────────
    try:
        contratos_raw = fetch_contratos(cnpj)
        for c in contratos_raw:
            entities.append(_normalize_contrato(c, _strip_cnpj(cnpj)))
        metadata["contratos_encontrados"] = len(contratos_raw)
        logger.info("gov_provider: %d contratos encontrados para %s", len(contratos_raw), cnpj)
    except Exception as e:
        errors.append(f"contratos: {e}")

    # ── CEIS ─────────────────────────────────────────────────────────────────
    try:
        ceis_raw = fetch_ceis(cnpj)
        for s in ceis_raw:
            entities.append(_normalize_sancao(s, _strip_cnpj(cnpj), "sancao_ceis"))
        metadata["sancoes_ceis"] = len(ceis_raw)
        if ceis_raw:
            metadata["tem_sancao_ativa"] = True
            logger.warning("gov_provider: empresa %s consta no CEIS (%d registros)", cnpj, len(ceis_raw))
    except Exception as e:
        errors.append(f"ceis: {e}")

    # ── CNEP ─────────────────────────────────────────────────────────────────
    try:
        cnep_raw = fetch_cnep(cnpj)
        for s in cnep_raw:
            entities.append(_normalize_sancao(s, _strip_cnpj(cnpj), "sancao_cnep"))
        metadata["sancoes_cnep"] = len(cnep_raw)
        if cnep_raw:
            metadata["tem_sancao_ativa"] = True
    except Exception as e:
        errors.append(f"cnep: {e}")

    # ── Telefone comercial (dado derivado) ───────────────────────────────────
    if telefone_publico:
        try:
            entities.append(_normalize_telefone_publico(telefone_publico, _strip_cnpj(cnpj)))
        except Exception as e:
            errors.append(f"telefone: {e}")

    return ProviderResult(
        provider="gov_provider",
        target=_strip_cnpj(cnpj),
        entities=entities,
        errors=errors,
        metadata=metadata,
    )