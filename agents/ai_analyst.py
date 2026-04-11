"""
ai_analyst.py — Motor de Inteligência do Sentinel OSINT

Pipeline: collector → validator → infra_agent → enrichment_agent → correlator → [ai_analyst]
Providers suportados: groq | openrouter | ollama

Arquitetura Multi-IA (quando Ollama disponível):
  - Ollama local (modelo leve) comprime contexto grande antes de enviar ao Groq
  - Isso resolve truncamento por limite de tokens e reduz custo de API
  - Ativado automaticamente quando contexto > _COMPRESSION_THRESHOLD chars
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

_MAX_CONTEXT_CHARS        = 32_000
_COMPRESSION_THRESHOLD    = 24_000
_MAX_SUBDOMAINS_IN_CONTEXT = 20
_MAX_SANS_IN_CONTEXT       = 15
_MAX_CVE_IN_CONTEXT        = 10
_MAX_BANNER_CHARS          = 120


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
    priority_level   : Optional[str] = Field(None, description="CRÍTICO|ALTO|MÉDIO|BAIXO|INFO")
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
    return "\n".join(parts)


# ── Truncamento de contexto ───────────────────────────────────────────────

def _truncate_enrichment_sources(sources: dict) -> dict:
    import copy
    s = copy.deepcopy(sources)

    subs      = s.get("subdomains", {})
    all_subs: list = subs.get("subdomains", [])
    total     = subs.get("count", len(all_subs))
    if total > _MAX_SUBDOMAINS_IN_CONTEXT:
        s["subdomains"] = {
            "count" : total,
            "sample": all_subs[:_MAX_SUBDOMAINS_IN_CONTEXT],
            "note"  : f"{total - _MAX_SUBDOMAINS_IN_CONTEXT} subdomínios omitidos — total: {total}",
        }

    for shodan in s.get("shodan", []):
        for svc in shodan.get("services", []):
            banner = svc.get("banner", "")
            if len(banner) > _MAX_BANNER_CHARS:
                svc["banner"] = banner[:_MAX_BANNER_CHARS] + "...[truncado]"
            if len(svc.get("cves", [])) > _MAX_CVE_IN_CONTEXT:
                svc["cves"] = svc["cves"][:_MAX_CVE_IN_CONTEXT]
        if len(shodan.get("all_cves", [])) > _MAX_CVE_IN_CONTEXT:
            shodan["all_cves"] = shodan["all_cves"][:_MAX_CVE_IN_CONTEXT]

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


def _build_enrichment_block(enrichment_data: dict) -> list[str]:
    s                 = enrichment_data.get("summary", {})
    sources_truncated = _truncate_enrichment_sources(enrichment_data.get("sources", {}))

    summary_subs: list = s.get("subdomains", [])
    sub_count  = s.get("subdomain_count", len(summary_subs))
    sub_display = ", ".join(summary_subs[:_MAX_SUBDOMAINS_IN_CONTEXT])
    if sub_count > _MAX_SUBDOMAINS_IN_CONTEXT:
        sub_display += f" ... (+{sub_count - _MAX_SUBDOMAINS_IN_CONTEXT} omitidos)"

    summary_cves: list = s.get("cves", [])
    cves_display = ", ".join(summary_cves[:_MAX_CVE_IN_CONTEXT])
    if len(summary_cves) > _MAX_CVE_IN_CONTEXT:
        cves_display += f" ... (+{len(summary_cves) - _MAX_CVE_IN_CONTEXT} omitidos)"

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
    """
    Monta bloco de subdomínios para o contexto do LLM.
    Prioriza takeover candidates — são os dados mais críticos.
    """
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

    # Lista de ativos — limitada para não inflar o contexto
    active_list = [
        s for s in subdomain_data.get("subdomains", [])
        if s.get("status") == "resolved"
    ][:_MAX_SUBDOMAINS_IN_CONTEXT]

    if active_list:
        lines.append("")
        lines.append(f"Ativos (amostra de {len(active_list)}):")
        for s in active_list:
            ips = ", ".join(s.get("ips", []))
            lines.append(f"  - {s['name']} → {ips}")

    return lines


def _build_header_block(header_data: dict) -> list[str]:
    """
    Monta bloco de análise de headers para o contexto do LLM.
    Inclui findings já classificados com MITRE — o LLM consolida, não reanalisa.
    """
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
            sev  = f.get("severity", "?")
            title = f.get("title", "?")
            mid  = f.get("mitre_id", "")
            ev   = f.get("evidence", "")[:120]
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
        "Exemplos VALIDOS:",
        "  Identificar OpenSSH 6.6.1 no banner via: nmap -sV -p22 45.33.32.156",
        "  Executar brute force: hydra -l root -P rockyou.txt 45.33.32.156 ssh",
        "  Obter shell com credencial valida -- controle total do host",
        "",
        "Exemplos INVALIDOS (nao use):",
        "  Explorar a porta 22 / Obter acesso nao autorizado / Executar codigo malicioso",
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
            "Kill chain: 1. Identificar CNAME para servico nao reivindicado",
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
        import ollama as ollama_client
        response = ollama_client.chat(
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
            "messages"   : [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": data_context},
            ],
        },
        timeout=120,
    )
    if response.status_code != 200:
        raise RuntimeError(f"OpenRouter retornou {response.status_code}: {response.text[:300]}")
    return response.json()["choices"][0]["message"]["content"]


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
    provider = os.getenv("AI_PROVIDER", "groq").lower().strip()
    model    = os.getenv("AI_MODEL", "llama-3.3-70b-versatile").strip()
    fallback = os.getenv("OLLAMA_FALLBACK_MODEL", "").strip()

    logger.info(f"[ai_analyst] Provider: {provider} | Modelo: {model}")

    if (
        provider in ("groq", "openrouter")
        and len(data_context) > _COMPRESSION_THRESHOLD
    ):
        data_context = _compress_context_ollama(data_context)

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


# ── Entry point ───────────────────────────────────────────────────────────

def run(
    collected_data  : dict,
    validation      : Optional[dict] = None,
    shodan_data     : Optional[dict] = None,
    correlator_data : Optional[dict] = None,
    enrichment_data : Optional[dict] = None,
    subdomain_data  : Optional[dict] = None,   # ← subdomain_agent
    header_data     : Optional[dict] = None,   # ← header_agent
) -> dict:
    """
    Args:
        collected_data  → collector  (WHOIS, DNS)                        [obrigatório]
        validation      → validator  (score, checks)                     [opcional]
        shodan_data     → infra_agent (portas, serviços)                 [opcional]
        correlator_data → correlator  (pares, scores)                    [opcional]
        enrichment_data → enrichment_agent (subdomínios, CVEs, HTTP,
                          reputação, SSL)                                [opcional]
        subdomain_data  → subdomain_agent (crt.sh + DNS + takeover)     [opcional]
        header_data     → header_agent (headers HTTP + cookies + CORS)  [opcional]
    """
    is_ip  = collected_data.get("is_ip", False)
    target = collected_data.get("ip") if is_ip else collected_data.get("domain", "desconhecido")
    if not target:
        target = "desconhecido"

    logger.info(f"[ai_analyst] Iniciando análise para: {target}")

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
        context_parts += _build_enrichment_block(enrichment_data)

    # blocos dos novos agentes
    if subdomain_data and "error" not in subdomain_data:
        context_parts += _build_subdomain_block(subdomain_data)

    if header_data and "error" not in header_data:
        context_parts += _build_header_block(header_data)

    # instrução final — agora ciente dos novos agentes
    context_parts.append(
        _build_analysis_instruction(enrichment_data, subdomain_data, header_data)
    )

    data_context = "\n".join(context_parts)

    if len(data_context) > _MAX_CONTEXT_CHARS:
        original_len = len(data_context)
        data_context = data_context[:_MAX_CONTEXT_CHARS] + \
                       "\n...[contexto truncado — limite atingido]"
        logger.warning(
            f"[ai_analyst] Contexto truncado no safety net: "
            f"{original_len} → {_MAX_CONTEXT_CHARS} chars"
        )

    logger.debug(f"[ai_analyst] Tamanho do contexto: {len(data_context)} chars")

    try:
        raw_response = call_model(system_prompt, data_context)
    except Exception as e:
        logger.error(f"[ai_analyst] Todos os providers falharam: {e}")
        analysis = _error_output(f"Todos os providers falharam: {e}")
        analysis.update({
            "target"     : target,
            "analyzed_at": datetime.now().isoformat(),
            "provider"   : os.getenv("AI_PROVIDER", "groq"),
            "model"      : os.getenv("AI_MODEL", "llama-3.3-70b-versatile"),
        })
        analysis["saved_to"] = save_analysis(target, analysis)
        return analysis

    analysis = parse_response(raw_response)
    analysis.update({
        "target"     : target,
        "analyzed_at": datetime.now().isoformat(),
        "provider"   : os.getenv("AI_PROVIDER", "groq"),
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