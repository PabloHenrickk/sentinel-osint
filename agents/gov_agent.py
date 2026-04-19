"""
gov_agent.py — Inteligência Governamental do Sentinel OSINT

Consome a API do Portal da Transparência (CGU) para cruzar um CNPJ com:
  - Contratos do Poder Executivo Federal
  - Sanções CEIS (Empresas Inidôneas e Suspensas)
  - Sanções CNEP (Empresas Punidas)
  - Convênios e repasses

Recebe o dict normalizado do input_resolver (requires_gov_agent=True).
Retorna JSON estruturado compatível com o ai_analyst.

Rate limits documentados (Portal da Transparência):
  - 00:00–06:00 → 700 req/min
  - Demais horários → 400 req/min
  - APIs restritas → 180 req/min
  - Suspensão do token por 8h se exceder

Para um CNPJ, o agente dispara no máximo 4 requests.
Um sleep de 0.2s entre calls é mais que suficiente.
"""

import os
import time
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

load_dotenv()

logger = logging.getLogger(__name__)

# ── Configuração ──────────────────────────────────────────────────────────

BASE_URL    = "https://api.portaldatransparencia.gov.br/api-de-dados"
API_KEY     = os.getenv("TRANSPARENCIA_API_KEY", "")
TIMEOUT     = 15          # segundos por request
SLEEP_BETWEEN = 0.2       # segundos entre calls — safe buffer no rate limit
MAX_ITEMS   = 50          # itens por página — padrão da API é 5, máximo 100


# ── Pydantic — Schema de saída ────────────────────────────────────────────

class ContractRecord(BaseModel):
    """Representa um contrato do Poder Executivo Federal."""
    number: str = Field("", alias="numero")
    object_description: str = Field("", alias="objeto")
    value: float = Field(0.0, alias="valorContratado")
    start_date: str = Field("", alias="dataInicioVigencia")
    end_date: str = Field("", alias="dataFimVigencia")
    organ: str = Field("", alias="orgao")
    situation: str = Field("", alias="situacao")

    model_config = {"populate_by_name": True}

    @field_validator("value", mode="before")
    @classmethod
    def parse_value(cls, v):
        """Aceita string, float ou None — normaliza para float."""
        if v is None:
            return 0.0
        try:
            return float(str(v).replace(",", "."))
        except (ValueError, TypeError):
            return 0.0


class SanctionRecord(BaseModel):
    """Representa uma entrada de sanção (CEIS ou CNEP)."""
    type: str = ""           # "CEIS" ou "CNEP" — preenchido pelo agente
    reason: str = Field("", alias="fundamentacaoLegal")
    start_date: str = Field("", alias="dataInicioSancao")
    end_date: str = Field("", alias="dataFinalSancao")
    sanctioning_organ: str = Field("", alias="orgaoSancionador")
    sanction_type: str = Field("", alias="tipoSancao")

    model_config = {"populate_by_name": True}


class ConvenioRecord(BaseModel):
    """Representa um convênio ou repasse."""
    number: str = Field("", alias="numero")
    object_description: str = Field("", alias="objeto")
    value: float = Field(0.0, alias="valorConvenio")
    grant_value: float = Field(0.0, alias="valorRepasse")
    start_date: str = Field("", alias="dataInicioVigencia")
    organ: str = Field("", alias="orgao")
    situation: str = Field("", alias="situacao")

    model_config = {"populate_by_name": True}

    @field_validator("value", "grant_value", mode="before")
    @classmethod
    def parse_value(cls, v):
        if v is None:
            return 0.0
        try:
            return float(str(v).replace(",", "."))
        except (ValueError, TypeError):
            return 0.0


class GovSummary(BaseModel):
    """Resumo executivo dos dados governamentais."""
    total_contracts: int = 0
    total_contract_value: float = 0.0
    total_convenios: int = 0
    total_grant_value: float = 0.0
    is_sanctioned: bool = False
    sanction_count: int = 0
    risk_level: str = "LOW"     # LOW | MEDIUM | HIGH | CRITICAL


class GovAgentOutput(BaseModel):
    """Schema completo de saída do gov_agent."""
    cnpj: str
    cnpj_formatted: str
    contracts: list[ContractRecord] = []
    sanctions_ceis: list[SanctionRecord] = []
    sanctions_cnep: list[SanctionRecord] = []
    convenios: list[ConvenioRecord] = []
    summary: GovSummary = Field(default_factory=GovSummary)
    gov_intel_findings: list[dict] = []
    source: str = "Portal da Transparência / CGU"
    timestamp: str = ""
    errors: list[str] = []


# ── HTTP helper ───────────────────────────────────────────────────────────

def _get(endpoint: str, params: dict) -> Optional[list]:
    """
    Executa GET autenticado contra a API do Portal da Transparência.

    Args:
        endpoint: caminho após BASE_URL (ex: "/contratos")
        params:   query params — cnpj, pagina, etc.

    Returns:
        lista de dicts com os dados, ou None se falhar.
    """
    if not API_KEY:
        logger.warning("gov_agent: TRANSPARENCIA_API_KEY não configurada — pulando")
        return None

    url = f"{BASE_URL}{endpoint}"
    headers = {
        "chave-api-dados": API_KEY,
        "Accept": "application/json",
    }

    # A API exige pagina + itens para paginação — defaults seguros
    params.setdefault("pagina", 1)
    params.setdefault("itens", MAX_ITEMS)

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            # A API retorna lista ou dict com lista — normaliza sempre para list
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                # Alguns endpoints encapsulam em chave "data" ou "content"
                for key in ("data", "content", "registros"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
                return [data]
            return []

        if resp.status_code == 401:
            logger.error("gov_agent: API key inválida ou expirada (401)")
        elif resp.status_code == 429:
            logger.warning("gov_agent: Rate limit atingido (429) — aguardando 5s")
            time.sleep(5)
        elif resp.status_code == 404:
            logger.debug("gov_agent: Nenhum registro encontrado em %s", endpoint)
            return []
        else:
            logger.warning("gov_agent: %s retornou HTTP %d", endpoint, resp.status_code)

    except requests.exceptions.Timeout:
        logger.error("gov_agent: Timeout em %s (>%ds)", endpoint, TIMEOUT)
    except requests.exceptions.ConnectionError:
        logger.error("gov_agent: Falha de conexão em %s", endpoint)
    except Exception as exc:
        logger.error("gov_agent: Erro inesperado em %s — %s", endpoint, exc)

    return None


# ── Coleta por endpoint ───────────────────────────────────────────────────

def _fetch_contracts(cnpj: str) -> tuple[list[ContractRecord], Optional[str]]:
    """Busca contratos do Poder Executivo onde a empresa é fornecedora."""
    raw = _get("/contratos", {"cnpjFornecedor": cnpj})
    time.sleep(SLEEP_BETWEEN)

    if raw is None:
        return [], "Falha na consulta de contratos"

    records = []
    for item in raw:
        try:
            records.append(ContractRecord.model_validate(item))
        except Exception:
            # Parse parcial — ignora item malformado, não abandona a lista
            continue

    return records, None


def _fetch_ceis(cnpj: str) -> tuple[list[SanctionRecord], Optional[str]]:
    """Busca sanções CEIS (Cadastro de Empresas Inidôneas e Suspensas)."""
    raw = _get("/ceis", {"cnpjSancionado": cnpj})
    time.sleep(SLEEP_BETWEEN)

    if raw is None:
        return [], "Falha na consulta CEIS"

    records = []
    for item in raw:
        try:
            r = SanctionRecord.model_validate(item)
            r.type = "CEIS"
            records.append(r)
        except Exception:
            continue

    return records, None


def _fetch_cnep(cnpj: str) -> tuple[list[SanctionRecord], Optional[str]]:
    """Busca sanções CNEP (Cadastro Nacional de Empresas Punidas)."""
    raw = _get("/cnep", {"cnpjSancionado": cnpj})
    time.sleep(SLEEP_BETWEEN)

    if raw is None:
        return [], "Falha na consulta CNEP"

    records = []
    for item in raw:
        try:
            r = SanctionRecord.model_validate(item)
            r.type = "CNEP"
            records.append(r)
        except Exception:
            continue

    return records, None


def _fetch_convenios(cnpj: str) -> tuple[list[ConvenioRecord], Optional[str]]:
    """Busca convênios onde a empresa é parceira/beneficiária."""
    raw = _get("/convenios", {"cnpjFornecedor": cnpj})
    time.sleep(SLEEP_BETWEEN)

    if raw is None:
        return [], "Falha na consulta de convênios"

    records = []
    for item in raw:
        try:
            records.append(ConvenioRecord.model_validate(item))
        except Exception:
            continue

    return records, None


# ── Análise e geração de findings ─────────────────────────────────────────

def _calculate_risk(summary: GovSummary) -> str:
    """
    Classifica o risco governamental com base nos dados coletados.

    Lógica:
        CRITICAL → qualquer sanção ativa (CEIS ou CNEP)
        HIGH     → contratos > R$ 10M ou > 10 contratos ativos
        MEDIUM   → contratos encontrados sem sanções
        LOW      → sem contratos e sem sanções
    """
    if summary.is_sanctioned:
        return "CRITICAL"
    if summary.total_contracts > 10 or summary.total_contract_value > 10_000_000:
        return "HIGH"
    if summary.total_contracts > 0:
        return "MEDIUM"
    return "LOW"


def _generate_findings(output: GovAgentOutput) -> list[dict]:
    """
    Gera findings estruturados compatíveis com o formato do ai_analyst.
    Cada finding pode ser incorporado diretamente no JSON de análise.
    """
    findings = []

    # Finding de sanção — sempre CRITICAL
    if output.sanctions_ceis or output.sanctions_cnep:
        all_sanctions = output.sanctions_ceis + output.sanctions_cnep
        types = list({s.type for s in all_sanctions})
        findings.append({
            "title": f"Empresa com sanções governamentais ativas ({', '.join(types)})",
            "severity": "CRITICAL",
            "category": "Gov Intelligence",
            "mitre_id": "T1588",
            "mitre_name": "Obtain Capabilities",
            "description": (
                f"CNPJ {output.cnpj_formatted} consta em {len(all_sanctions)} registro(s) "
                f"de sanção nos cadastros: {', '.join(types)}. "
                "Empresas sancionadas têm histórico de irregularidades com o governo federal."
            ),
            "evidence": [
                f"{s.type}: {s.sanction_type} — {s.sanctioning_organ} ({s.start_date})"
                for s in all_sanctions[:5]    # limita a 5 exemplos no finding
            ],
            "recommendation": (
                "Verificar se a empresa ainda possui contratos ativos com o governo. "
                "Avaliar exposição a riscos de compliance e de continuidade de serviços."
            ),
            "source": "Portal da Transparência / CEIS / CNEP",
            "kill_chain": [
                "Identificação de empresa sancionada via CEIS/CNEP",
                "Cruzamento com contratos ativos do Executivo Federal",
                "Avaliação de impacto na cadeia de fornecimento",
            ],
        })

    # Finding de volume contratual elevado
    if output.summary.total_contract_value > 10_000_000:
        findings.append({
            "title": "Alto volume de contratos governamentais federais",
            "severity": "HIGH",
            "category": "Gov Intelligence",
            "mitre_id": "T1591",
            "mitre_name": "Gather Victim Org Information",
            "description": (
                f"Empresa possui {output.summary.total_contracts} contrato(s) com o governo federal, "
                f"totalizando R$ {output.summary.total_contract_value:,.2f}. "
                "Alvos com alto volume contratual têm incentivo elevado para adversários — "
                "acesso aos sistemas pode comprometer dados governamentais sensíveis."
            ),
            "evidence": [
                f"Contrato {c.number}: {c.object_description[:80]} — R$ {c.value:,.2f}"
                for c in output.contracts[:5]
            ],
            "recommendation": (
                "Verificar postura de segurança dos sistemas integrados ao governo. "
                "Avaliar exposição de APIs e portais de acesso a dados federais."
            ),
            "source": "Portal da Transparência / Contratos",
            "kill_chain": [],
        })

    # Finding de presença governamental (informacional)
    elif output.summary.total_contracts > 0:
        findings.append({
            "title": "Empresa com contratos ativos no governo federal",
            "severity": "MEDIUM",
            "category": "Gov Intelligence",
            "mitre_id": "T1591",
            "mitre_name": "Gather Victim Org Information",
            "description": (
                f"Empresa possui {output.summary.total_contracts} contrato(s) com o governo federal "
                f"totalizando R$ {output.summary.total_contract_value:,.2f}."
            ),
            "evidence": [
                f"Contrato {c.number}: {c.object_description[:80]}"
                for c in output.contracts[:3]
            ],
            "recommendation": "Manter postura de segurança adequada ao nível de acesso governamental.",
            "source": "Portal da Transparência / Contratos",
            "kill_chain": [],
        })

    return findings


# ── Entry point ───────────────────────────────────────────────────────────

def run(normalized: dict) -> dict:
    """
    Entry point principal do gov_agent.

    Args:
        normalized: dict do input_resolver com target=CNPJ (14 dígitos), 
                    metadata["cnpj_formatted"] já populado.

    Returns:
        dict compatível com GovAgentOutput — sempre retorna estrutura válida,
        nunca propaga exceções para o pipeline.
    """
    cnpj          = normalized.get("target", "")
    cnpj_formatted = normalized.get("metadata", {}).get("cnpj_formatted", cnpj)
    errors: list[str] = []

    logger.info("gov_agent: iniciando análise de CNPJ %s", cnpj_formatted)

    if not cnpj:
        return {
            "error": "gov_agent: CNPJ não fornecido",
            "cnpj": "",
            "cnpj_formatted": "",
            "summary": {"risk_level": "UNKNOWN"},
        }

    if not API_KEY:
        logger.warning("gov_agent: TRANSPARENCIA_API_KEY ausente — retornando estrutura vazia")
        return {
            "error": "gov_agent: TRANSPARENCIA_API_KEY não configurada",
            "cnpj": cnpj,
            "cnpj_formatted": cnpj_formatted,
            "summary": {"risk_level": "UNKNOWN"},
        }

    # ── Coleta paralela independente por endpoint ─────────────────────────
    contracts, err = _fetch_contracts(cnpj)
    if err:
        errors.append(err)

    sanctions_ceis, err = _fetch_ceis(cnpj)
    if err:
        errors.append(err)

    sanctions_cnep, err = _fetch_cnep(cnpj)
    if err:
        errors.append(err)

    convenios, err = _fetch_convenios(cnpj)
    if err:
        errors.append(err)

    # ── Calcula sumário ───────────────────────────────────────────────────
    total_value  = sum(c.value for c in contracts)
    grant_value  = sum(c.grant_value for c in convenios)
    is_sanctioned = bool(sanctions_ceis or sanctions_cnep)

    summary = GovSummary(
        total_contracts      = len(contracts),
        total_contract_value = total_value,
        total_convenios      = len(convenios),
        total_grant_value    = grant_value,
        is_sanctioned        = is_sanctioned,
        sanction_count       = len(sanctions_ceis) + len(sanctions_cnep),
        risk_level           = "UNKNOWN",   # será calculado abaixo
    )
    summary.risk_level = _calculate_risk(summary)

    # ── Monta output completo ─────────────────────────────────────────────
    output = GovAgentOutput(
        cnpj            = cnpj,
        cnpj_formatted  = cnpj_formatted,
        contracts       = contracts,
        sanctions_ceis  = sanctions_ceis,
        sanctions_cnep  = sanctions_cnep,
        convenios       = convenios,
        summary         = summary,
        timestamp       = datetime.now(timezone.utc).isoformat(),
        errors          = errors,
    )
    output.gov_intel_findings = _generate_findings(output)

    logger.info(
        "gov_agent: concluído — contratos=%d, sanções=%d, risco=%s",
        summary.total_contracts,
        summary.sanction_count,
        summary.risk_level,
    )

    return output.model_dump()