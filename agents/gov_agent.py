"""
gov_agent.py — Inteligência Governamental do Sentinel OSINT

Consome a API do Portal da Transparência (CGU) e BrasilAPI para cruzar
um CNPJ com contratos, sanções, convênios e padrões suspeitos de gasto.

Camadas de inteligência:
  Camada 1 — Coleta:   contratos, sanções, convênios via Portal da Transparência
  Camada 2 — Padrões:  sobrepreço, fracionamento, volume contratual
  Camada 3 — HUMINT:   perfil societário, incompatibilidades, anomalias cadastrais

A camada HUMINT mapeia o vetor humano do alvo — quem está por trás da empresa,
se o perfil cadastral é compatível com os contratos e se há sinais de testa de ferro.
Todos os dados são públicos (Lei de Acesso à Informação + Decreto 8.777/2016).

Rate limits (Portal da Transparência):
  - 00:00–06:00: 700 req/min | Demais: 400 req/min
  - Suspensão do token por 8h se exceder

BUGS CORRIGIDOS:
  - _get(): 'itens' -> 'tamanhoPagina' (param correto da API v3)
  - _fetch_convenios(): 'cnpjFornecedor' -> 'cnpjConvenente'
"""

import os
import re
import time
import logging
from datetime import datetime, timezone, date
from typing import Optional

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

load_dotenv()

logger = logging.getLogger(__name__)

# Configuracao
BASE_URL          = "https://api.portaldatransparencia.gov.br/api-de-dados"
BRASILAPI_URL     = "https://brasilapi.com.br/api/cnpj/v1"
API_KEY           = os.getenv("TRANSPARENCIA_API_KEY", "")
TIMEOUT           = 15
SLEEP_BETWEEN     = 0.2
MAX_ITEMS         = 50
DISPENSA_THRESHOLD  = 17_600.00
EMPRESA_NOVA_ANOS   = 2
CAPITAL_RATIO_ALERT = 0.05
CAPITAL_RATIO_CRIT  = 0.01
CONTRATO_ALTO_VALOR = 500_000.00

PRICE_REFERENCES: dict[str, tuple[float, float]] = {
    "mouse":           (30.0,     500.0),
    "teclado":         (50.0,     800.0),
    "notebook":        (1_500.0,  8_000.0),
    "computador":      (1_500.0, 12_000.0),
    "desktop":         (1_500.0, 10_000.0),
    "monitor":         (400.0,   3_000.0),
    "impressora":      (300.0,   5_000.0),
    "papel":           (15.0,      50.0),
    "caneta":          (1.0,       20.0),
    "cadeira":         (200.0,   3_000.0),
    "ar condicionado": (1_500.0, 15_000.0),
    "servidor":        (5_000.0, 80_000.0),
    "switch":          (500.0,   20_000.0),
    "roteador":        (200.0,   15_000.0),
    "nobreak":         (300.0,   8_000.0),
    "pendrive":        (20.0,     200.0),
    "hd externo":      (150.0,    800.0),
    "webcam":          (80.0,     600.0),
    "headset":         (50.0,     800.0),
}

_RE_QTD = re.compile(r"\b(\d{1,4})\s*(?:un(?:idades?)?|pc|pecas?|itens?)?\.?\s", re.IGNORECASE)

# CNAE divisao (2 digitos) -> keywords esperadas no objeto de contratos
CNAE_KEYWORDS: dict[str, list[str]] = {
    "62": ["software", "sistema", "desenvolvimento", "ti", "tecnologia", "aplicativo",
           "plataforma", "licenca", "suporte tecnico", "manutencao de sistema"],
    "63": ["dados", "informacao", "internet", "hosting", "cloud", "servidor"],
    "41": ["construcao", "obra", "edificacao", "reforma", "ampliacao"],
    "42": ["infraestrutura", "pavimentacao", "saneamento", "drenagem"],
    "43": ["instalacao eletrica", "hidraulica", "manutencao predial", "ar condicionado"],
    "47": ["material", "equipamento", "produto", "fornecimento", "aquisicao"],
    "56": ["alimentacao", "refeicao", "cafe", "lanche", "marmita", "restaurante"],
    "86": ["saude", "medico", "hospitalar", "equipamento medico", "ambulancia"],
    "85": ["educacao", "capacitacao", "treinamento", "curso", "formacao"],
    "78": ["mao de obra", "trabalhadores", "funcionarios", "terceirizacao"],
    "80": ["seguranca", "vigilancia", "monitoramento", "escolta"],
    "81": ["limpeza", "higienizacao", "manutencao predial", "conservacao"],
    "49": ["transporte", "frete", "logistica", "veiculo", "onibus"],
    "77": ["locacao", "aluguel", "arrendamento", "cessao de uso"],
    "71": ["consultoria", "assessoria", "engenharia", "arquitetura", "laudo"],
    "73": ["publicidade", "propaganda", "comunicacao", "marketing", "midia"],
    "69": ["advocacia", "juridico", "contabilidade", "auditoria"],
    "70": ["gestao", "consultoria empresarial", "planejamento"],
}


# Schemas

class ContractRecord(BaseModel):
    id: str = Field("", alias="id")
    number: str = Field("", alias="numero")
    object_description: str = Field("", alias="objeto")
    value: float = Field(0.0, alias="valorContratado")
    start_date: str = Field("", alias="dataInicioVigencia")
    end_date: str = Field("", alias="dataFimVigencia")
    organ: str = Field("", alias="orgao")
    situation: str = Field("", alias="situacao")
    modality: str = Field("", alias="modalidadeCompra")
    process_number: str = Field("", alias="numeroProcesso")
    model_config = {"populate_by_name": True}

    @field_validator("value", mode="before")
    @classmethod
    def parse_value(cls, v):
        if v is None:
            return 0.0
        try:
            return float(str(v).replace(",", "."))
        except (ValueError, TypeError):
            return 0.0


class SanctionRecord(BaseModel):
    type: str = ""
    reason: str = Field("", alias="fundamentacaoLegal")
    start_date: str = Field("", alias="dataInicioSancao")
    end_date: str = Field("", alias="dataFinalSancao")
    sanctioning_organ: str = Field("", alias="orgaoSancionador")
    sanction_type: str = Field("", alias="tipoSancao")
    model_config = {"populate_by_name": True}


class ConvenioRecord(BaseModel):
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


class PartnerRecord(BaseModel):
    """
    Socio da empresa extraido do QSA (Quadro Societario e Administrativo).

    O CPF na Receita Federal e parcialmente mascarado (ex: ***123456**).
    Util para identificacao por nome e cruzamento manual com TSE.
    Para cruzamento TSE: nome + municipio + faixa etaria.
    """
    name: str = ""
    cpf_masked: str = ""
    qualification: str = ""
    entry_date: str = ""
    age_bracket: str = ""
    legal_representative: str = ""


class ProfileFlag(BaseModel):
    """
    Sinal de alerta do perfil HUMINT da empresa.
    Cada flag e um indicador isolado. A convergencia de multiplos flags
    eleva o risco mesmo sem prova formal de irregularidade.
    """
    flag_type: str
    severity: str
    title: str
    detail: str
    evidence: list[str] = []
    investigative_note: str = ""


class CompanyInfo(BaseModel):
    """Dados cadastrais da empresa via BrasilAPI (Receita Federal). Inclui QSA."""
    razao_social: str = ""
    nome_fantasia: str = ""
    cnae_principal: str = ""
    cnae_descricao: str = ""
    email: str = ""
    telefone: str = ""
    municipio: str = ""
    uf: str = ""
    domain_hint: str = ""
    porte: str = ""
    capital_social: float = 0.0
    data_abertura: str = ""
    situacao_cadastral: str = ""
    partners: list[PartnerRecord] = []


class PriceAnomaly(BaseModel):
    contract_number: str
    object_description: str
    contract_value: float
    keyword_matched: str
    estimated_quantity: int
    unit_price: float
    max_reasonable: float
    overprice_factor: float
    organ: str
    severity: str


class FractioningPattern(BaseModel):
    organ: str
    contract_count: int
    total_value: float
    contracts_below_threshold: int
    threshold_used: float = DISPENSA_THRESHOLD
    suspicion_score: int


class GovSummary(BaseModel):
    total_contracts: int = 0
    total_contract_value: float = 0.0
    total_convenios: int = 0
    total_grant_value: float = 0.0
    is_sanctioned: bool = False
    sanction_count: int = 0
    price_anomalies: int = 0
    fractioning_patterns: int = 0
    profile_flags: int = 0
    has_humint_flags: bool = False
    risk_level: str = "LOW"


class GovAgentOutput(BaseModel):
    cnpj: str
    cnpj_formatted: str
    company_info: CompanyInfo = Field(default_factory=CompanyInfo)
    contracts: list[ContractRecord] = []
    sanctions_ceis: list[SanctionRecord] = []
    sanctions_cnep: list[SanctionRecord] = []
    convenios: list[ConvenioRecord] = []
    price_anomalies: list[PriceAnomaly] = []
    fractioning_patterns: list[FractioningPattern] = []
    humint_flags: list[ProfileFlag] = []
    summary: GovSummary = Field(default_factory=GovSummary)
    gov_intel_findings: list[dict] = []
    source: str = "Portal da Transparencia / CGU + BrasilAPI / Receita Federal"
    timestamp: str = ""
    errors: list[str] = []


# HTTP helpers

def _get(endpoint: str, params: dict) -> Optional[list]:
    """GET autenticado contra a API do Portal da Transparencia."""
    if not API_KEY:
        logger.warning("gov_agent: TRANSPARENCIA_API_KEY nao configurada")
        return None

    url     = f"{BASE_URL}{endpoint}"
    headers = {"chave-api-dados": API_KEY, "Accept": "application/json"}
    params.setdefault("pagina", 1)
    params.setdefault("tamanhoPagina", MAX_ITEMS)   # CORRECAO: nao 'itens'

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("data", "content", "registros"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
                return [data]
            return []
        if resp.status_code == 401:
            logger.error("gov_agent: API key invalida (401)")
        elif resp.status_code == 429:
            logger.warning("gov_agent: Rate limit (429) — aguardando 5s")
            time.sleep(5)
        elif resp.status_code == 404:
            return []
        else:
            logger.warning("gov_agent: %s HTTP %d — %s",
                           endpoint, resp.status_code, resp.text[:200])
    except requests.exceptions.Timeout:
        logger.error("gov_agent: Timeout em %s", endpoint)
    except requests.exceptions.ConnectionError:
        logger.error("gov_agent: Falha de conexao em %s", endpoint)
    except Exception as exc:
        logger.error("gov_agent: Erro em %s — %s", endpoint, exc)
    return None


def _get_brasilapi(cnpj: str) -> Optional[dict]:
    """Receita Federal via BrasilAPI — sem autenticacao."""
    try:
        resp = requests.get(f"{BRASILAPI_URL}/{cnpj}", timeout=TIMEOUT,
                            headers={"Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        logger.warning("gov_agent: BrasilAPI falhou — %s", exc)
    return None


# Coleta por endpoint

def _parse_partners(raw_qsa: list) -> list[PartnerRecord]:
    """Parseia QSA retornado pela BrasilAPI. CPF mascarado pela Receita Federal."""
    partners = []
    for entry in raw_qsa or []:
        try:
            partners.append(PartnerRecord(
                name               = str(entry.get("nome_socio", "") or "").strip(),
                cpf_masked         = str(entry.get("cnpj_cpf_do_socio", "") or "").strip(),
                qualification      = str(entry.get("qualificacao_socio", "") or "").strip(),
                entry_date         = str(entry.get("data_entrada_sociedade", "") or "").strip(),
                age_bracket        = str(entry.get("faixa_etaria", "") or "").strip(),
                legal_representative = str(entry.get("nome_representante_legal", "") or "").strip(),
            ))
        except Exception:
            continue
    return partners


def _fetch_company_info(cnpj: str) -> tuple[CompanyInfo, Optional[str]]:
    """Dados cadastrais + QSA via BrasilAPI. Infere dominio do email."""
    raw = _get_brasilapi(cnpj)
    if not raw:
        return CompanyInfo(), "BrasilAPI: sem dados para este CNPJ"

    cnae_codigo = cnae_descricao = ""
    atividade = raw.get("atividade_principal", [])
    if atividade:
        cnae_codigo    = str(atividade[0].get("code", ""))
        cnae_descricao = str(atividade[0].get("text", ""))

    email       = (raw.get("email", "") or "").strip().lower()
    domain_hint = ""
    if "@" in email:
        candidate = email.split("@")[1].strip().lower()
        generic   = {"gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
                     "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br"}
        if candidate not in generic:
            domain_hint = candidate

    def _s(key: str) -> str:
        return str(raw.get(key, "") or "").strip()

    capital = 0.0
    try:
        capital = float(raw.get("capital_social", 0) or 0)
    except (ValueError, TypeError):
        pass

    return CompanyInfo(
        razao_social       = _s("razao_social"),
        nome_fantasia      = _s("nome_fantasia"),
        cnae_principal     = cnae_codigo,
        cnae_descricao     = cnae_descricao,
        email              = email,
        telefone           = _s("ddd_telefone_1"),
        municipio          = _s("municipio"),
        uf                 = _s("uf"),
        domain_hint        = domain_hint,
        porte              = _s("porte"),
        capital_social     = capital,
        data_abertura      = _s("data_inicio_atividade"),
        situacao_cadastral = _s("descricao_situacao_cadastral"),
        partners           = _parse_partners(raw.get("qsa", [])),
    ), None


def _fetch_contracts(cnpj: str) -> tuple[list[ContractRecord], Optional[str]]:
    raw = _get("/contratos", {"cnpjFornecedor": cnpj})
    time.sleep(SLEEP_BETWEEN)
    if raw is None:
        return [], "Falha na consulta de contratos"
    records = []
    for item in raw:
        try:
            records.append(ContractRecord.model_validate(item))
        except Exception:
            continue
    return records, None


def _fetch_ceis(cnpj: str) -> tuple[list[SanctionRecord], Optional[str]]:
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
    """CORRECAO: cnpjConvenente (nao cnpjFornecedor — causa HTTP 400)."""
    raw = _get("/convenios", {"cnpjConvenente": cnpj})
    time.sleep(SLEEP_BETWEEN)
    if raw is None:
        return [], "Falha na consulta de convenios"
    records = []
    for item in raw:
        try:
            records.append(ConvenioRecord.model_validate(item))
        except Exception:
            continue
    return records, None


# Analise financeira

def _analyze_price_anomalies(contracts: list[ContractRecord]) -> list[PriceAnomaly]:
    """Detecta sobreprecao comparando preco unitario implicito com referencia de mercado."""
    anomalies = []
    for contract in contracts:
        obj = contract.object_description.lower()
        for keyword, (_, max_price) in PRICE_REFERENCES.items():
            if keyword not in obj:
                continue
            m        = _RE_QTD.search(obj)
            quantity = int(m.group(1)) if m else 1
            unit     = contract.value / quantity if quantity > 0 else contract.value
            if unit <= max_price * 3:
                continue
            factor   = round(unit / max_price, 1)
            severity = "CRITICAL" if factor >= 10 else "HIGH"
            anomalies.append(PriceAnomaly(
                contract_number    = contract.number,
                object_description = contract.object_description[:120],
                contract_value     = contract.value,
                keyword_matched    = keyword,
                estimated_quantity = quantity,
                unit_price         = round(unit, 2),
                max_reasonable     = max_price,
                overprice_factor   = factor,
                organ              = contract.organ,
                severity           = severity,
            ))
            break
    return anomalies


def _analyze_fractioning(contracts: list[ContractRecord]) -> list[FractioningPattern]:
    """Detecta fracionamento artificial — multiplos contratos abaixo do limiar de licitacao."""
    by_organ: dict[str, list[ContractRecord]] = {}
    for c in contracts:
        by_organ.setdefault(c.organ or "DESCONHECIDO", []).append(c)

    patterns = []
    for organ, ocs in by_organ.items():
        below = [c for c in ocs if 0 < c.value <= DISPENSA_THRESHOLD]
        if len(below) < 2:
            continue
        total = sum(c.value for c in ocs)
        score = min(len(below) * 20, 60)
        if total > 100_000:
            score += 30
        if len(below) > 5:
            score += 20
        patterns.append(FractioningPattern(
            organ=organ, contract_count=len(ocs),
            total_value=round(total, 2),
            contracts_below_threshold=len(below),
            suspicion_score=min(score, 100),
        ))
    return sorted(patterns, key=lambda p: p.suspicion_score, reverse=True)


# Analise HUMINT

def _parse_date(date_str: str) -> Optional[date]:
    """Parseia data ISO ou BR. Retorna None se invalido."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_str[:10], fmt).date()
        except ValueError:
            continue
    return None


def _check_empresa_nova(
    company: CompanyInfo,
    contracts: list[ContractRecord],
) -> Optional[ProfileFlag]:
    """
    Empresa jovem ganhando contratos de alto valor.

    Padrao classico de testa de ferro: empresa aberta poucos meses antes
    de uma licitacao direcionada. Capital baixo, sem historico, sem estrutura
    — mas ganha o contrato de R$10M.
    """
    if not company.data_abertura:
        return None
    abertura = _parse_date(company.data_abertura)
    if not abertura:
        return None

    hoje       = date.today()
    idade_anos = (hoje - abertura).days / 365.25
    altos      = [c for c in contracts if c.value >= CONTRATO_ALTO_VALOR]

    if not altos or idade_anos >= EMPRESA_NOVA_ANOS:
        return None

    maior    = max(altos, key=lambda c: c.value)
    severity = "CRITICAL" if idade_anos < 0.5 else "HIGH"

    return ProfileFlag(
        flag_type = "EMPRESA_NOVA",
        severity  = severity,
        title     = f"Empresa com {idade_anos:.1f} ano(s) — contrato de R${maior.value:,.2f}",
        detail    = (
            f"Data de abertura: {company.data_abertura}. "
            f"Idade na analise: {idade_anos:.1f} anos. "
            f"Contratos de alto valor: {len(altos)}."
        ),
        evidence  = [
            f"Abertura: {company.data_abertura}",
            f"Porte: {company.porte or 'nao informado'}",
            f"Maior contrato: R${maior.value:,.2f} — {maior.object_description[:60]}",
            f"Orgao: {maior.organ}",
        ],
        investigative_note = (
            "Verificar: socios (QSA) e se tem vinculos com agentes publicos do orgao contratante. "
            "Cruzar data de abertura com data do edital. "
            "Consultar Compras.gov.br pelo numero do processo licitatorio."
        ),
    )


def _check_capital_incompativel(
    company: CompanyInfo,
    total_contract_value: float,
) -> Optional[ProfileFlag]:
    """
    Capital social incompativel com o volume contratado.

    Uma empresa com capital de R$1.000 nao tem capacidade economica para
    executar um contrato de R$5M. Pode ser casca para desviar recursos.
    Base legal: art. 67 Lei 14.133/2021 exige qualificacao economico-financeira.
    """
    if company.capital_social <= 0 or total_contract_value <= 0:
        return None
    ratio = company.capital_social / total_contract_value
    if ratio >= CAPITAL_RATIO_ALERT:
        return None

    severity = "CRITICAL" if ratio < CAPITAL_RATIO_CRIT else "HIGH"
    return ProfileFlag(
        flag_type = "CAPITAL_INCOMPATIVEL",
        severity  = severity,
        title     = (
            f"Capital social (R${company.capital_social:,.2f}) = "
            f"{ratio*100:.2f}% do total contratado (R${total_contract_value:,.2f})"
        ),
        detail    = (
            f"Capital declarado: R${company.capital_social:,.2f}. "
            f"Total contratado: R${total_contract_value:,.2f}. "
            f"Razao: {ratio*100:.2f}% (limiar: {CAPITAL_RATIO_ALERT*100:.0f}%)."
        ),
        evidence  = [
            f"Capital social: R${company.capital_social:,.2f}",
            f"Total contratado: R${total_contract_value:,.2f}",
            f"Razao: {ratio*100:.2f}%",
            f"Porte: {company.porte or 'nao informado'}",
        ],
        investigative_note = (
            "Verificar garantias contratuais apresentadas (caucao, fianca bancaria). "
            "Consultar balanco patrimonial via Junta Comercial. "
            "Capital abaixo de 10% do contrato pode indicar habilitacao irregular — "
            "art. 67 III, Lei 14.133/2021."
        ),
    )


def _check_cnae_incompativel(
    company: CompanyInfo,
    contracts: list[ContractRecord],
) -> Optional[ProfileFlag]:
    """
    CNAE da empresa incompativel com o objeto dos contratos.

    Empresa de 'alimentacao' ganhando contrato de 'desenvolvimento de software'
    = sinal claro de direcionamento ou testa de ferro.
    """
    if not company.cnae_principal or not contracts:
        return None

    cnae_clean  = re.sub(r"[.\-/]", "", company.cnae_principal)
    cnae_div    = cnae_clean[:2]
    expected_kw = CNAE_KEYWORDS.get(cnae_div)
    if not expected_kw:
        return None

    incompatible = [
        c for c in contracts
        if not any(kw in c.object_description.lower() for kw in expected_kw)
    ]

    # Flagga somente se TODOS os contratos sao incompativeis (evita falso positivo)
    if not incompatible or len(incompatible) < len(contracts):
        return None

    return ProfileFlag(
        flag_type = "CNAE_INCOMPATIVEL",
        severity  = "HIGH",
        title     = (
            f"CNAE '{company.cnae_descricao}' incompativel com "
            f"{len(incompatible)} contrato(s)"
        ),
        detail    = (
            f"Atividade registrada: '{company.cnae_descricao}'. "
            f"Espera termos como: {', '.join(expected_kw[:4])}. "
            f"Nenhum dos {len(contracts)} contrato(s) contem esses termos."
        ),
        evidence  = [
            f"CNAE: {company.cnae_principal} — {company.cnae_descricao}",
            f"Termos esperados: {', '.join(expected_kw[:4])}",
            *[f"Contrato: '{c.object_description[:60]}'" for c in incompatible[:3]],
        ],
        investigative_note = (
            "Verificar CNAEs secundarios (nao aparecem na BrasilAPI v1 — consultar Junta Comercial). "
            "Incompatibilidade total sugere empresa criada para contrato especifico (testa de ferro). "
            "Acionar TCU/CGU se confirmado o direcionamento licitatorio."
        ),
    )


def _check_situacao_cadastral(
    company: CompanyInfo,
    contracts: list[ContractRecord],
) -> Optional[ProfileFlag]:
    """
    Empresa inapta/irregular na Receita mas com contratos ativos.
    Empresa inapta nao deveria ser habilitada em licitacoes.
    """
    situacao     = company.situacao_cadastral.upper()
    is_irregular = any(s in situacao for s in ("INAPTA", "BAIXADA", "SUSPENSA", "IRREGULAR"))
    if not is_irregular or not contracts:
        return None

    ativas = [c for c in contracts
              if "vigente" in c.situation.lower() or "ativo" in c.situation.lower()]

    return ProfileFlag(
        flag_type = "SITUACAO_INAPTA",
        severity  = "CRITICAL",
        title     = f"Empresa '{company.situacao_cadastral}' com contratos governamentais",
        detail    = (
            f"Situacao Receita Federal: '{company.situacao_cadastral}'. "
            f"Contratos ativos: {len(ativas) if ativas else len(contracts)}."
        ),
        evidence  = [
            f"Situacao: {company.situacao_cadastral}",
            f"Total contratos: {len(contracts)}",
            f"Contratos ativos: {len(ativas)}",
        ],
        investigative_note = (
            "Verificar SICAF — orgao deveria ter identificado a irregularidade na habilitacao. "
            "Se contrato firmado apos inaptidao, pode configurar improbidade administrativa "
            "do agente responsavel (Lei 8.429/1992)."
        ),
    )


def _check_socio_unico(
    company: CompanyInfo,
    total_contract_value: float,
) -> Optional[ProfileFlag]:
    """
    Empresa unipessoal com alto volume contratual.
    Mais facil de operar como laranja — sem outros socios para questionar decisoes.
    """
    if len(company.partners) != 1 or total_contract_value < CONTRATO_ALTO_VALOR:
        return None

    socio = company.partners[0]
    return ProfileFlag(
        flag_type = "SOCIO_UNICO_ALTO_VALOR",
        severity  = "MEDIUM",
        title     = f"Empresa unipessoal — R${total_contract_value:,.2f} em contratos",
        detail    = (
            f"Unico socio: {socio.name} ({socio.qualification}). "
            f"Controle centralizado facilita operacao como testa de ferro."
        ),
        evidence  = [
            f"Socio unico: {socio.name}",
            f"Qualificacao: {socio.qualification}",
            f"Entrada na sociedade: {socio.entry_date or 'nao informado'}",
            f"Faixa etaria: {socio.age_bracket or 'nao informado'}",
            f"Total contratado: R${total_contract_value:,.2f}",
        ],
        investigative_note = (
            f"Pesquisar '{socio.name}' + municipio + 'politico' / 'vereador' / 'servidor'. "
            "Cruzar com dadosabertos.tse.jus.br (aba candidatos — busca por nome). "
            "Verificar outros CNPJs do mesmo socio (busca por nome na Junta Comercial)."
        ),
    )


def _analyze_humint_profile(
    company: CompanyInfo,
    contracts: list[ContractRecord],
    total_value: float,
) -> list[ProfileFlag]:
    """Executa todos os checks HUMINT. Cada check e independente."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    flags = []

    for check_fn, args in [
        (_check_situacao_cadastral, (company, contracts)),
        (_check_empresa_nova,       (company, contracts)),
        (_check_capital_incompativel, (company, total_value)),
        (_check_cnae_incompativel,  (company, contracts)),
        (_check_socio_unico,        (company, total_value)),
    ]:
        try:
            flag = check_fn(*args)
            if flag is not None:
                flags.append(flag)
        except Exception as exc:
            logger.warning("gov_agent: HUMINT check %s falhou — %s", check_fn.__name__, exc)

    return sorted(flags, key=lambda f: severity_order.get(f.severity, 99))


# Calculo de risco

def _calculate_risk(summary: GovSummary) -> str:
    if summary.is_sanctioned or summary.price_anomalies > 0:
        return "CRITICAL"
    if summary.has_humint_flags and summary.profile_flags >= 2:
        return "HIGH"
    if (summary.total_contracts > 10
            or summary.total_contract_value > 10_000_000
            or summary.fractioning_patterns > 0
            or summary.has_humint_flags):
        return "HIGH"
    if summary.total_contracts > 0:
        return "MEDIUM"
    return "LOW"


# Geracao de findings

def _generate_findings(output: GovAgentOutput) -> list[dict]:
    findings: list[dict] = []

    if output.sanctions_ceis or output.sanctions_cnep:
        all_s = output.sanctions_ceis + output.sanctions_cnep
        types = list({s.type for s in all_s})
        findings.append({
            "title":    f"Sancoes governamentais ativas ({', '.join(types)})",
            "severity": "CRITICAL",
            "category": "Gov Intelligence",
            "mitre_id": "T1588", "mitre_name": "Obtain Capabilities",
            "description": (
                f"CNPJ {output.cnpj_formatted} em {len(all_s)} registro(s): {', '.join(types)}."
            ),
            "evidence": [
                f"{s.type}: {s.sanction_type} — {s.sanctioning_organ} ({s.start_date})"
                for s in all_s[:5]
            ],
            "recommendation": "Verificar contratos ativos. Avaliar riscos de compliance.",
            "source": "Portal da Transparencia / CEIS / CNEP",
            "kill_chain": [
                "Identificacao via CEIS/CNEP",
                "Cruzamento com contratos ativos",
                "Avaliacao de impacto na cadeia de fornecimento",
            ],
        })

    for a in output.price_anomalies:
        findings.append({
            "title":    f"Sobreprecao detectado — {a.keyword_matched} ({a.severity})",
            "severity": a.severity,
            "category": "Gov Intelligence",
            "mitre_id": "T1591.002",
            "mitre_name": "Gather Victim Org Information: Business Relationships",
            "description": (
                f"Contrato {a.contract_number} com {a.organ}: '{a.object_description}' "
                f"— R${a.contract_value:,.2f}. "
                f"Preco unitario: R${a.unit_price:,.2f} ({a.overprice_factor:.1f}x acima de R${a.max_reasonable:,.2f})."
            ),
            "evidence": [
                f"Objeto: {a.object_description}",
                f"Quantidade estimada: {a.estimated_quantity} unidades",
                f"Preco unitario: R${a.unit_price:,.2f}",
                f"Referencia mercado: R${a.max_reasonable:,.2f}/unidade",
                f"Fator sobreprecao: {a.overprice_factor:.1f}x",
            ],
            "recommendation": "Cruzar com Compras.gov.br. Reportar TCU/CGU se confirmado.",
            "source": "Portal da Transparencia / Contratos",
            "kill_chain": [
                "Identificacao via PRICE_REFERENCES",
                "Estimativa preco unitario (objeto + regex quantidade)",
                "Comparacao com referencia de mercado",
                "Flag para revisao humana",
            ],
        })

    alerta = [p for p in output.fractioning_patterns if p.suspicion_score >= 60]
    if alerta:
        w = alerta[0]
        findings.append({
            "title":    f"Fracionamento de contratos — {w.organ} (score {w.suspicion_score}/100)",
            "severity": "HIGH",
            "category": "Gov Intelligence",
            "mitre_id": "T1591", "mitre_name": "Gather Victim Org Information",
            "description": (
                f"{w.contracts_below_threshold} contratos abaixo de R${DISPENSA_THRESHOLD:,.0f} "
                f"com {w.organ}, total R${w.total_value:,.2f}. Viola art. 72 Lei 14.133/2021."
            ),
            "evidence": [
                f"{p.contracts_below_threshold} contratos <= R${DISPENSA_THRESHOLD:,.0f} "
                f"com {p.organ} (score {p.suspicion_score}/100)"
                for p in alerta[:3]
            ],
            "recommendation": "Verificar datas dos contratos. Acionar CGU/TCU se confirmado.",
            "source": "Portal da Transparencia / Contratos",
            "kill_chain": [
                "Agrupamento por orgao",
                "Contagem abaixo do limiar",
                "Calculo valor acumulado vs limiar",
                "Scoring 0-100",
            ],
        })

    # Findings HUMINT — um por flag
    for flag in output.humint_flags:
        findings.append({
            "title":    flag.title,
            "severity": flag.severity,
            "category": "HUMINT / Perfil Societario",
            "mitre_id": "T1591.001",
            "mitre_name": "Gather Victim Org Information: Determine Physical Locations",
            "description": flag.detail,
            "evidence":    flag.evidence,
            "recommendation": flag.investigative_note,
            "source":   "BrasilAPI / Receita Federal",
            "kill_chain": [
                "Coleta cadastral via BrasilAPI",
                "Analise de QSA e situacao cadastral",
                f"Deteccao: {flag.flag_type}",
                "Flag para investigacao humana — dados publicos",
            ],
        })

    # Volume contratual
    if output.summary.total_contracts > 0 and not output.sanctions_ceis:
        sev = "HIGH" if output.summary.total_contract_value > 10_000_000 else "MEDIUM"
        findings.append({
            "title":    f"{output.summary.total_contracts} contrato(s) — R${output.summary.total_contract_value:,.2f}",
            "severity": sev,
            "category": "Gov Intelligence",
            "mitre_id": "T1591", "mitre_name": "Gather Victim Org Information",
            "description": f"Total de contratos federais: {output.summary.total_contracts}.",
            "evidence": [
                f"Contrato {c.number}: {c.object_description[:80]} — R${c.value:,.2f}"
                for c in output.contracts[:5]
            ],
            "recommendation": "Verificar postura de seguranca dos sistemas integrados ao governo.",
            "source": "Portal da Transparencia / Contratos",
            "kill_chain": [],
        })

    # Dominio corporativo
    if output.company_info.domain_hint:
        findings.append({
            "title":    "Dominio corporativo identificado via Receita Federal",
            "severity": "INFO",
            "category": "Gov Intelligence",
            "mitre_id": "T1590", "mitre_name": "Gather Victim Network Information",
            "description": (
                f"Dominio inferido: '{output.company_info.domain_hint}'. "
                f"Empresa: {output.company_info.razao_social}."
            ),
            "evidence": [
                f"Email Receita Federal: {output.company_info.email}",
                f"Dominio inferido: {output.company_info.domain_hint}",
                f"CNAE: {output.company_info.cnae_principal} — {output.company_info.cnae_descricao}",
            ],
            "recommendation": (
                f"Adicionar '{output.company_info.domain_hint}' ao pipeline tecnico "
                "para analise DNS, WHOIS, Shodan, headers."
            ),
            "source": "BrasilAPI / Receita Federal",
            "kill_chain": [
                "Extracao de email via CNPJ",
                "Inferencia de dominio corporativo",
                "Injecao no pipeline tecnico OSINT",
            ],
        })

    # QSA — socios para cruzamento TSE
    if output.company_info.partners:
        partners = output.company_info.partners
        findings.append({
            "title":    f"QSA: {len(partners)} socio(s) — verificar vinculos politicos",
            "severity": "INFO",
            "category": "HUMINT / Perfil Societario",
            "mitre_id": "T1591.001",
            "mitre_name": "Gather Victim Org Information",
            "description": (
                f"Quadro societario com {len(partners)} membro(s). "
                "CPFs mascarados pela Receita Federal. "
                "Cruzamento com TSE requer pesquisa manual por nome."
            ),
            "evidence": [
                f"{p.name} | {p.qualification} | entrada: {p.entry_date or 'N/A'} | faixa: {p.age_bracket or 'N/A'}"
                for p in partners[:5]
            ],
            "recommendation": (
                "Pesquisar cada nome em dadosabertos.tse.jus.br (candidatos). "
                "Verificar se socios sao servidores do orgao contratante "
                "(conflito de interesses — Lei 12.813/2013)."
            ),
            "source": "BrasilAPI / Receita Federal (QSA)",
            "kill_chain": [
                "Extracao QSA via BrasilAPI",
                "Listagem de socios com qualificacao e data de entrada",
                "Flag para cruzamento manual com TSE e SIAPE",
            ],
        })

    return findings


# Entry point

def run(normalized: dict) -> dict:
    """
    Entry point principal do gov_agent.
    Nunca propaga excecoes para o pipeline.
    """
    cnpj           = normalized.get("target", "")
    cnpj_formatted = normalized.get("metadata", {}).get("cnpj_formatted", cnpj)
    errors: list[str] = []

    logger.info("gov_agent: CNPJ %s", cnpj_formatted)

    if not cnpj:
        return {"error": "gov_agent: CNPJ nao fornecido", "cnpj": "",
                "cnpj_formatted": "", "summary": {"risk_level": "UNKNOWN"}}
    if not API_KEY:
        return {"error": "gov_agent: TRANSPARENCIA_API_KEY nao configurada",
                "cnpj": cnpj, "cnpj_formatted": cnpj_formatted,
                "summary": {"risk_level": "UNKNOWN"}}

    company_info, err = _fetch_company_info(cnpj)
    if err:
        errors.append(err)

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

    total_value          = sum(c.value for c in contracts)
    price_anomalies      = _analyze_price_anomalies(contracts)
    fractioning_patterns = _analyze_fractioning(contracts)
    humint_flags         = _analyze_humint_profile(company_info, contracts, total_value)

    is_sanctioned = bool(sanctions_ceis or sanctions_cnep)
    summary = GovSummary(
        total_contracts      = len(contracts),
        total_contract_value = round(total_value, 2),
        total_convenios      = len(convenios),
        total_grant_value    = round(sum(c.grant_value for c in convenios), 2),
        is_sanctioned        = is_sanctioned,
        sanction_count       = len(sanctions_ceis) + len(sanctions_cnep),
        price_anomalies      = len(price_anomalies),
        fractioning_patterns = len(fractioning_patterns),
        profile_flags        = len(humint_flags),
        has_humint_flags     = bool(humint_flags),
        risk_level           = "UNKNOWN",
    )
    summary.risk_level = _calculate_risk(summary)

    output = GovAgentOutput(
        cnpj=cnpj, cnpj_formatted=cnpj_formatted,
        company_info=company_info, contracts=contracts,
        sanctions_ceis=sanctions_ceis, sanctions_cnep=sanctions_cnep,
        convenios=convenios, price_anomalies=price_anomalies,
        fractioning_patterns=fractioning_patterns,
        humint_flags=humint_flags, summary=summary,
        timestamp=datetime.now(timezone.utc).isoformat(),
        errors=errors,
    )
    output.gov_intel_findings = _generate_findings(output)

    logger.info(
        "gov_agent: contratos=%d | sancoes=%d | anomalias=%d | humint=%d | risco=%s",
        summary.total_contracts, summary.sanction_count,
        summary.price_anomalies, summary.profile_flags, summary.risk_level,
    )
    return output.model_dump()