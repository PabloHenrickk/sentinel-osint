"""
cnpj_provider.py — Dados de empresa via CNPJ

Fontes em fallback sequencial:
  1. BrasilAPI     — melhor qualidade, sem token
  2. ReceitaWS     — fallback 1, sem token
  3. CNPJ.ws       — fallback 2, sem token

Retorna: empresa normalizada com sócios (QSA), CNAE,
situação cadastral, endereço e relações para o grafo.

Por que sócios são o dado mais valioso:
  CNPJ → sócios → outras empresas do mesmo sócio
  Essa cadeia revela estruturas corporativas que
  não aparecem em nenhuma análise técnica de infra.
"""

import re
import time
from typing import Any, Optional

import requests

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger
from providers.base import (
    BaseProvider,
    NormalizedEntity,
    ProviderResult,
    build_relation,
    clamp_confidence,
    safe_query,
)

logger = get_logger(__name__)

_TIMEOUT = 15


# ── Helpers ───────────────────────────────────────────────────

def _clean_cnpj(raw: str) -> str:
    """Remove formatação — retorna 14 dígitos."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 14:
        raise ValueError(
            f"CNPJ inválido: '{raw}' — esperado 14 dígitos, "
            f"obtido {len(digits)}"
        )
    return digits


def _format_cnpj(digits: str) -> str:
    return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}"


def _validate_cnpj(digits: str) -> bool:
    """Valida dígitos verificadores — rejeita CNPJs fake."""
    if len(digits) != 14 or len(set(digits)) == 1:
        return False

    def calc(d: str, weights: list[int]) -> int:
        r = sum(int(x) * w for x, w in zip(d, weights)) % 11
        return 0 if r < 2 else 11 - r

    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    return (
        int(digits[12]) == calc(digits[:12], w1)
        and int(digits[13]) == calc(digits[:13], w2)
    )


def _extract_socios(qsa: list[dict]) -> list[dict]:
    """
    Normaliza a lista de sócios independente do formato da fonte.
    BrasilAPI e ReceitaWS retornam QSA com campos ligeiramente diferentes.
    """
    socios = []
    for s in qsa or []:
        nome = (
            s.get("nome_socio")
            or s.get("nome")
            or s.get("name")
            or "Desconhecido"
        )
        qualificacao = (
            s.get("qualificacao_socio")
            or s.get("qual")
            or s.get("qualificacao")
            or ""
        )
        cnpj_socio = re.sub(r"\D", "", s.get("cnpj_cpf_do_socio") or s.get("cnpj") or "")
        socios.append({
            "nome"        : nome.strip().upper(),
            "qualificacao": qualificacao,
            "cnpj_cpf"    : cnpj_socio or None,
        })
    return socios


# ── Fonte 1: BrasilAPI ────────────────────────────────────────

class BrasilAPISource:
    """
    BrasilAPI — melhor qualidade, sem autenticação.
    Retorna CNPJ completo com QSA (sócios).
    """
    name       = "brasilapi"
    confidence = 0.95

    def fetch(self, cnpj: str) -> Optional[dict]:
        url = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj}"
        logger.info(f"[cnpj_provider] BrasilAPI → {cnpj}")
        r = requests.get(url, timeout=_TIMEOUT)
        if r.status_code == 429:
            logger.warning("[cnpj_provider] BrasilAPI rate limit")
            return None
        if r.status_code == 404:
            logger.info("[cnpj_provider] BrasilAPI: CNPJ não encontrado")
            return None
        r.raise_for_status()
        return r.json()


# ── Fonte 2: ReceitaWS ────────────────────────────────────────

class ReceitaWSSource:
    """
    ReceitaWS — fallback 1.
    Schema levemente diferente do BrasilAPI — normalização cobre isso.
    """
    name       = "receitaws"
    confidence = 0.85

    def fetch(self, cnpj: str) -> Optional[dict]:
        url = f"https://www.receitaws.com.br/v1/cnpj/{cnpj}"
        logger.info(f"[cnpj_provider] ReceitaWS → {cnpj}")
        # ReceitaWS exige delay entre requests no free tier
        time.sleep(1.0)
        r = requests.get(url, timeout=_TIMEOUT)
        if r.status_code in (429, 503):
            logger.warning("[cnpj_provider] ReceitaWS rate limit / indisponível")
            return None
        if r.status_code == 400:
            return None
        r.raise_for_status()
        data = r.json()
        # ReceitaWS retorna {"status": "ERROR"} para CNPJs inválidos
        if data.get("status") == "ERROR":
            return None
        return data


# ── Fonte 3: CNPJ.ws ─────────────────────────────────────────

class CNPJwsSource:
    """
    CNPJ.ws — fallback 2.
    Mais permissivo em rate limit que os anteriores.
    """
    name       = "cnpjws"
    confidence = 0.80

    def fetch(self, cnpj: str) -> Optional[dict]:
        url = f"https://publica.cnpj.ws/cnpj/{cnpj}"
        logger.info(f"[cnpj_provider] CNPJ.ws → {cnpj}")
        r = requests.get(url, timeout=_TIMEOUT)
        if r.status_code in (404, 429):
            return None
        r.raise_for_status()
        return r.json()


# ── Normalizador unificado ────────────────────────────────────

def _normalize_company(
    raw       : dict,
    source    : str,
    confidence: float,
    cnpj      : str,
) -> list[NormalizedEntity]:
    """
    Transforma dado bruto de qualquer fonte em NormalizedEntity.

    Cada aspecto da empresa vira uma entidade separada:
      - empresa principal (razão social, situação, CNAE)
      - cada sócio (QSA) → entidade pessoa + relação tem_socio
      - endereço → metadata da empresa principal

    Por que separar sócios em entidades próprias:
      O grafo precisa de nós independentes para computar
      relações como sócio → outras empresas.
      Se sócio ficar só como metadata, o grafo não consegue
      navegar a partir dele.
    """
    entities: list[NormalizedEntity] = []

    # ── campos com múltiplos nomes possíveis por fonte ────────
    razao = (
        raw.get("razao_social")
        or raw.get("nome")
        or raw.get("company")
        or "Não informado"
    ).strip().upper()

    situacao = (
        raw.get("descricao_situacao_cadastral")
        or raw.get("situacao")
        or raw.get("status")
        or "DESCONHECIDA"
    ).strip().upper()

    cnae_code = (
        raw.get("cnae_fiscal")
        or raw.get("atividade_principal", [{}])[0].get("code", "")
        if isinstance(raw.get("atividade_principal"), list)
        else raw.get("cnae_fiscal", "")
    )
    cnae_desc = (
        raw.get("cnae_fiscal_descricao")
        or (raw.get("atividade_principal") or [{}])[0].get("text", "")
        if isinstance(raw.get("atividade_principal"), list)
        else ""
    )

    # endereço — unifica campos de diferentes schemas
    logradouro  = raw.get("logradouro")  or raw.get("street", "")
    municipio   = raw.get("municipio")   or raw.get("city", "")
    uf          = raw.get("uf")          or raw.get("state", "")
    cep_raw     = raw.get("cep")         or raw.get("zip", "")
    cep         = re.sub(r"\D", "", str(cep_raw))

    # relações base da empresa
    relations = []

    # QSA — sócios
    qsa_raw = raw.get("qsa") or raw.get("socios") or []
    socios  = _extract_socios(qsa_raw)

    for socio in socios:
        nome_socio = socio["nome"]
        relations.append(build_relation("tem_socio", nome_socio))

        # entidade pessoa para o grafo
        socio_entity = NormalizedEntity(
            entity_type = "pessoa",
            source      = source,
            data_type   = "socio",
            value       = nome_socio,
            confidence  = clamp_confidence(confidence - 0.05),
            metadata    = {
                "qualificacao": socio["qualificacao"],
                "cnpj_cpf"    : socio["cnpj_cpf"],
                "empresa_cnpj": cnpj,
                "empresa_nome": razao,
            },
            relations   = [build_relation("socio_de", razao)],
        )
        entities.append(socio_entity)

    # entidade principal da empresa
    empresa_entity = NormalizedEntity(
        entity_type = "empresa",
        source      = source,
        data_type   = "cnpj",
        value       = cnpj,
        confidence  = clamp_confidence(confidence),
        metadata    = {
            "razao_social"   : razao,
            "situacao"       : situacao,
            "cnae_codigo"    : str(cnae_code),
            "cnae_descricao" : cnae_desc,
            "logradouro"     : logradouro,
            "municipio"      : municipio,
            "uf"             : uf,
            "cep"            : cep,
            "socios"         : socios,
            "total_socios"   : len(socios),
            "ativa"          : "ATIVA" in situacao,
            "cnpj_formatted" : _format_cnpj(cnpj),
        },
        relations = relations,
    )
    entities.append(empresa_entity)

    logger.info(
        f"[cnpj_provider] Normalizado: {razao} | "
        f"Situação: {situacao} | Sócios: {len(socios)}"
    )
    return entities


# ── CNPJProvider — orquestrador com fallback ──────────────────

class CNPJProvider(BaseProvider):
    """
    Orquestra as três fontes em fallback sequencial.

    Ordem de tentativa:
      BrasilAPI (0.95) → ReceitaWS (0.85) → CNPJ.ws (0.80)

    A primeira que retornar dado válido encerra o ciclo.
    O confidence reflete qual fonte foi usada — dado
    do BrasilAPI tem mais peso no score de risco do grafo
    do que dado do CNPJ.ws.
    """

    name = "cnpj_provider"

    _sources = [
        BrasilAPISource(),
        ReceitaWSSource(),
        CNPJwsSource(),
    ]

    def _fetch(self, cnpj: str) -> Optional[dict]:
        """
        Tenta cada fonte em ordem.
        Retorna tupla (raw, source_name, confidence) para o normalizador.
        """
        for source in self._sources:
            result = safe_query(
                source.fetch,
                cnpj,
                retries     = 2,
                delay       = 1.0,
                source_name = source.name,
            )
            if result:
                # empacota fonte junto com o dado para o _normalize
                return {
                    "_raw"       : result,
                    "_source"    : source.name,
                    "_confidence": source.confidence,
                }

        logger.error(f"[cnpj_provider] Todas as fontes falharam para {cnpj}")
        return None

    def _normalize(self, raw: Any) -> list[NormalizedEntity]:
        return _normalize_company(
            raw        = raw["_raw"],
            source     = raw["_source"],
            confidence = raw["_confidence"],
            cnpj       = raw["_raw"].get("cnpj", ""),
        )

    def run(self, cnpj: str) -> ProviderResult:  # type: ignore[override]
        """
        Entry point público.
        Valida CNPJ antes de qualquer requisição — evita
        desperdiçar rate limit em CNPJs malformados.
        """
        errors: list[str] = []

        try:
            cnpj_digits = _clean_cnpj(cnpj)
        except ValueError as e:
            return ProviderResult(
                success  = False,
                entities = [],
                errors   = [str(e)],
                source   = self.name,
            )

        if not _validate_cnpj(cnpj_digits):
            return ProviderResult(
                success  = False,
                entities = [],
                errors   = [f"CNPJ {_format_cnpj(cnpj_digits)} inválido (dígitos verificadores)"],
                source   = self.name,
            )

        result = super().run(cnpj_digits)
        result.metadata["cnpj_queried"] = cnpj_digits
        return result


# ── Função de conveniência ────────────────────────────────────

def run(cnpj: str) -> dict:
    """
    Interface simples para uso direto no pipeline.
    Retorna dict compatível com o ai_analyst.
    """
    provider = CNPJProvider()
    result   = provider.run(cnpj)

    if not result.success:
        return {
            "error"  : result.errors[0] if result.errors else "Falha desconhecida",
            "cnpj"   : cnpj,
            "source" : result.source,
        }

    # extrai empresa principal e sócios do resultado
    empresa = next(
        (e for e in result.entities if e.data_type == "cnpj"),
        None,
    )
    socios  = [
        e for e in result.entities if e.data_type == "socio"
    ]

    if not empresa:
        return {"error": "Empresa não encontrada", "cnpj": cnpj}

    return {
        "cnpj"      : empresa.value,
        "source"    : empresa.source,
        "confidence": empresa.confidence,
        "company"   : empresa.metadata,
        "socios"    : [s.metadata for s in socios],
        "relations" : empresa.relations,
        "errors"    : result.errors,
    }