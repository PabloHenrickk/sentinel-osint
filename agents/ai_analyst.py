"""
ai_analyst.py — Motor de Inteligência do Sentinel OSINT

Recebe dados dos agentes anteriores, injeta Skills + memória persistente
e retorna análise estruturada via LLM com validação Pydantic.

Pipeline: collector → validator → shodan_agent → correlator → [ai_analyst]

Providers suportados: groq | openrouter | ollama
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

load_dotenv()

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger

logger = get_logger(__name__)

# ── caminhos ────────────────────────────────────────────────
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


# ── schemas Pydantic ─────────────────────────────────────────

class Finding(BaseModel):
    """Representa um achado individual da análise."""
    title      : str           = Field(..., description="Título curto do achado")
    severity   : str           = Field(..., description="CRÍTICO | ALTO | MÉDIO | BAIXO | INFO")
    description: str           = Field(..., description="Descrição técnica do achado")
    mitre_id   : Optional[str] = Field(None, description="ID da técnica MITRE ATT&CK")
    mitre_name : Optional[str] = Field(None, description="Nome da técnica MITRE ATT&CK")
    evidence   : Optional[str] = Field(None, description="Evidência que suporta o achado")


class AnalysisOutput(BaseModel):
    """Schema obrigatório de saída do ai_analyst."""
    priority_level   : str             = Field(..., description="CRÍTICO | ALTO | MÉDIO | BAIXO | INFO")
    executive_summary: str             = Field(..., description="Resumo executivo em 2-3 frases")
    findings         : list[Finding]   = Field(default_factory=list)
    threat_hypotheses: list[str]       = Field(default_factory=list)
    recommendations  : list[str]       = Field(default_factory=list)
    confidence_score : Optional[int]   = Field(None, ge=0, le=100)


def _error_output(reason: str, raw: str = "") -> dict:
    """Estrutura de erro padrão — nunca trava o pipeline."""
    return {
        "error"            : reason,
        "raw_response"     : raw[:500] if raw else "",
        "priority_level"   : "INDETERMINADO",
        "executive_summary": f"Análise falhou — {reason}",
        "findings"         : [],
        "threat_hypotheses": [],
        "recommendations"  : [],
    }


# ── carregamento de skills ───────────────────────────────────

def load_skills() -> str:
    """Carrega arquivos Markdown de Skills e concatena em string única."""
    content: list[str] = []
    for filename in SKILL_FILES:
        path = SKILLS_DIR / filename
        if path.exists():
            text = path.read_text(encoding="utf-8")
            content.append(f"## SKILL: {filename}\n{text}")
            logger.info(f"[ai_analyst] Skill carregada: {filename}")
        else:
            logger.warning(f"[ai_analyst] Skill não encontrada: {filename}")
    return "\n\n".join(content)


# ── carregamento de memória ──────────────────────────────────

def _load_json_file(path: Path, root_key: str) -> list:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get(root_key, [])
    except Exception as e:
        logger.error(f"[ai_analyst] Erro ao ler {path.name}: {e}")
        return []


def load_memory() -> dict:
    memory = {
        "patterns"   : _load_json_file(MEMORY_FILES["patterns"],    "patterns"),
        "corrections": _load_json_file(MEMORY_FILES["corrections"],  "corrections"),
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


# ── salvar na memória ────────────────────────────────────────

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
            "rule"      : rule,
            "context"   : context,
            "created_at": datetime.now().isoformat(),
        })
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[ai_analyst] Correção salva: {rule[:60]}...")
        return True
    except Exception as e:
        logger.error(f"[ai_analyst] Falha ao salvar correção: {e}")
        return False


def save_pattern(pattern: str, source: str = "") -> bool:
    try:
        path = MEMORY_FILES["patterns"]
        data = _ensure_memory_file(path, "patterns")
        data.setdefault("patterns", []).append({
            "pattern"   : pattern,
            "source"    : source,
            "created_at": datetime.now().isoformat(),
        })
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[ai_analyst] Padrão salvo: {pattern[:60]}...")
        return True
    except Exception as e:
        logger.error(f"[ai_analyst] Falha ao salvar padrão: {e}")
        return False


# ── montar system prompt ─────────────────────────────────────

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


# ── providers de IA ──────────────────────────────────────────

def call_groq(system_prompt: str, data_context: str, model: str) -> str:
    """
    Chama modelo via Groq API (compatível com OpenAI).
    Groq é o provider principal — mais rápido e gratuito no tier atual.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY não encontrada no .env")

    logger.info(f"[ai_analyst] Groq → modelo: {model}")

    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type" : "application/json",
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
        raise RuntimeError(
            f"Groq retornou {response.status_code}: {response.text[:300]}"
        )

    return response.json()["choices"][0]["message"]["content"]


def call_openrouter(system_prompt: str, data_context: str, model: str) -> str:
    """Chama modelo via OpenRouter."""
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
        raise RuntimeError(
            f"OpenRouter retornou {response.status_code}: {response.text[:300]}"
        )

    return response.json()["choices"][0]["message"]["content"]


def call_ollama(system_prompt: str, data_context: str, model: str) -> str:
    """Fallback local via Ollama. Import lazy — não quebra startup."""
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
        options={"temperature": 0.1, "num_predict": 2000},
    )
    return response["message"]["content"]


def call_model(system_prompt: str, data_context: str) -> str:
    """
    Roteia chamada para o provider configurado no .env.

    Hierarquia de fallback:
      groq       → falha → ollama
      openrouter → falha → ollama
      ollama     → sem fallback

    Providers válidos: groq | openrouter | ollama
    """
    provider = os.getenv("AI_PROVIDER", "groq").lower().strip()
    model    = os.getenv("AI_MODEL", "llama-3.3-70b-versatile").strip()
    fallback = os.getenv("OLLAMA_FALLBACK_MODEL", "llama3.1:8b").strip()

    logger.info(f"[ai_analyst] Provider: {provider} | Modelo: {model}")

    if provider == "groq":
        try:
            return call_groq(system_prompt, data_context, model)
        except Exception as e:
            logger.warning(f"[ai_analyst] Groq falhou ({e}). Fallback → Ollama/{fallback}")
            return call_ollama(system_prompt, data_context, fallback)

    elif provider == "openrouter":
        try:
            return call_openrouter(system_prompt, data_context, model)
        except Exception as e:
            logger.warning(f"[ai_analyst] OpenRouter falhou ({e}). Fallback → Ollama/{fallback}")
            return call_ollama(system_prompt, data_context, fallback)

    elif provider == "ollama":
        return call_ollama(system_prompt, data_context, model)

    else:
        raise ValueError(
            f"AI_PROVIDER inválido: '{provider}'. Use 'groq', 'openrouter' ou 'ollama'."
        )


# ── parsear e validar resposta ───────────────────────────────

def parse_response(raw: str) -> dict:
    """
    Extrai JSON da resposta do LLM com múltiplas estratégias de fallback.

    Estratégias (ordem):
      1. Parse direto do texto limpo
      2. Extração de bloco ```json ... ```
      3. Regex para encontrar objeto JSON no texto
      4. Estrutura de erro padronizada
    """
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

    logger.error(f"[ai_analyst] Todas as estratégias de parse falharam. Raw:\n{raw[:400]}")
    return _error_output("Modelo retornou formato inválido — JSON não encontrado", raw)


def _validate_output(data: dict, raw: str) -> dict:
    """
    Valida dict contra AnalysisOutput via Pydantic.
    Em falha parcial: preenche campos obrigatórios e registra warnings.
    """
    try:
        return AnalysisOutput(**data).model_dump()
    except ValidationError as e:
        logger.warning(
            f"[ai_analyst] Validação Pydantic falhou — {e.error_count()} erro(s). "
            f"Usando dados parciais."
        )
        data.setdefault("priority_level",    "INDETERMINADO")
        data.setdefault("executive_summary", "Resumo não gerado pelo modelo.")
        data.setdefault("findings",          [])
        data.setdefault("threat_hypotheses", [])
        data.setdefault("recommendations",   [])
        data["_validation_warnings"] = [str(err["msg"]) for err in e.errors()]
        return data


# ── salvar análise ───────────────────────────────────────────

def save_analysis(target: str, analysis: dict) -> str:
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # sanitiza target para nome de arquivo seguro
    safe_name = target.replace(".", "_").replace("/", "-").replace(":", "-")
    filename  = OUTPUT_DIR / f"{safe_name}_{timestamp}_ai_analysis.json"
    filename.write_text(
        json.dumps(analysis, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    logger.info(f"[ai_analyst] Análise salva: {filename}")
    return str(filename)


# ── função principal ─────────────────────────────────────────

def run(
    collected_data  : dict,
    validation      : Optional[dict] = None,
    shodan_data     : Optional[dict] = None,
    correlator_data : Optional[dict] = None,
) -> dict:
    """
    Função principal do AI Analyst.

    Args:
        collected_data  → output do collector  (WHOIS, DNS)         [obrigatório]
        validation      → output do validator  (score, checks)      [opcional]
        shodan_data     → output do infra_agent (portas, serviços)  [opcional]
        correlator_data → output do correlator  (pares, scores)     [opcional]

    Returns:
        dict com análise estruturada — nunca levanta exceção.
    """
    # resolve target corretamente para IP e domínio
    # is_ip garante que nunca lemos domain=None para IPs
    is_ip  = collected_data.get("is_ip", False)
    target = collected_data.get("ip") if is_ip else collected_data.get("domain", "desconhecido")
    if not target:
        target = "desconhecido"

    logger.info(f"[ai_analyst] Iniciando análise para: {target}")

    skills        = load_skills()
    memory        = load_memory()
    mem_str       = format_memory(memory)
    system_prompt = build_system_prompt(skills, mem_str)

    context_parts = [
        f"ALVO: {target}",
        "",
        "## DADOS WHOIS E DNS",
        json.dumps(collected_data, indent=2, ensure_ascii=False),
    ]

    if validation:
        context_parts += [
            "",
            "## VALIDAÇÃO",
            json.dumps(validation, indent=2, ensure_ascii=False),
        ]

    if shodan_data and "error" not in shodan_data:
        context_parts += [
            "",
            "## DADOS DE INFRAESTRUTURA (portas, serviços)",
            json.dumps(shodan_data, indent=2, ensure_ascii=False),
        ]

    if correlator_data and "error" not in correlator_data:
        context_parts += [
            "",
            "## CORRELAÇÃO (relações entre alvos)",
            json.dumps(correlator_data, indent=2, ensure_ascii=False),
        ]

    context_parts.append(
        "\nAnalise os dados acima e retorne JSON conforme o schema definido."
    )

    data_context = "\n".join(context_parts)

    try:
        raw_response = call_model(system_prompt, data_context)
    except Exception as e:
        logger.error(f"[ai_analyst] Todos os providers falharam: {e}")
        analysis = _error_output(f"Todos os providers falharam: {e}")
        analysis["target"]      = target
        analysis["analyzed_at"] = datetime.now().isoformat()
        analysis["provider"]    = os.getenv("AI_PROVIDER", "groq")
        analysis["model"]       = os.getenv("AI_MODEL", "llama-3.3-70b-versatile")
        analysis["saved_to"]    = save_analysis(target, analysis)
        return analysis

    analysis = parse_response(raw_response)
    analysis["target"]      = target
    analysis["analyzed_at"] = datetime.now().isoformat()
    analysis["provider"]    = os.getenv("AI_PROVIDER", "groq")
    analysis["model"]       = os.getenv("AI_MODEL", "llama-3.3-70b-versatile")
    analysis["saved_to"]    = save_analysis(target, analysis)

    logger.info(
        f"[ai_analyst] Concluído — Provider: {analysis['provider']} | "
        f"Prioridade: {analysis.get('priority_level', '?')} | "
        f"Achados: {len(analysis.get('findings', []))}"
    )

    return analysis