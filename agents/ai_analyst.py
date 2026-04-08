"""
ai_analyst.py — Motor de Inteligência do Sentinel OSINT

Recebe dados dos agentes anteriores, injeta Skills + memória persistente
e retorna análise estruturada via LLM com validação Pydantic.

Pipeline: collector → validator → shodan_agent → correlator → [ai_analyst]
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

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


# ── schemas Pydantic ─────────────────────────────────────────

class Finding(BaseModel):
    """Representa um achado individual da análise."""
    title      : str            = Field(..., description="Título curto do achado")
    severity   : str            = Field(..., description="CRÍTICO | ALTO | MÉDIO | BAIXO | INFO")
    description: str            = Field(..., description="Descrição técnica do achado")
    mitre_id   : Optional[str]  = Field(None, description="ID da técnica MITRE ATT&CK")
    mitre_name : Optional[str]  = Field(None, description="Nome da técnica MITRE ATT&CK")
    evidence   : Optional[str]  = Field(None, description="Evidência que suporta o achado")


class AnalysisOutput(BaseModel):
    """Schema obrigatório de saída do ai_analyst."""
    priority_level   : str          = Field(..., description="CRÍTICO | ALTO | MÉDIO | BAIXO | INFO")
    executive_summary: str          = Field(..., description="Resumo executivo em 2-3 frases")
    findings         : list[Finding] = Field(default_factory=list)
    threat_hypotheses: list[str]    = Field(default_factory=list, description="Hipóteses adversariais")
    recommendations  : list[str]    = Field(default_factory=list, description="Ações recomendadas")
    confidence_score : Optional[int] = Field(None, ge=0, le=100, description="Confiança 0-100")


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
    """Carrega lista de um arquivo JSON com chave raiz definida."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get(root_key, [])
    except Exception as e:
        logger.error(f"[ai_analyst] Erro ao ler {path.name}: {e}")
        return []


def load_memory() -> dict:
    """Carrega patterns e corrections da memória persistente."""
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
    """Formata memória como texto para injeção no system prompt."""
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
    """
    Garante que o arquivo de memória existe e é válido.
    Cria com estrutura vazia se não existir.
    """
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        initial = {root_key: []}
        path.write_text(json.dumps(initial, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[ai_analyst] Arquivo de memória criado: {path.name}")
        return initial
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"[ai_analyst] Arquivo corrompido {path.name}, recriando: {e}")
        initial = {root_key: []}
        path.write_text(json.dumps(initial, indent=2, ensure_ascii=False), encoding="utf-8")
        return initial


def save_correction(rule: str, context: str = "") -> bool:
    """
    Salva correção na memória persistente.
    Retorna True em sucesso, False em falha — nunca levanta exceção.
    """
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
    """
    Salva padrão identificado na memória persistente.
    Retorna True em sucesso, False em falha — nunca levanta exceção.
    """
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
    """Monta system prompt com Skills e memória ativa."""
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


# ── chamada OpenRouter ───────────────────────────────────────

def call_openrouter(system_prompt: str, data_context: str, model: str) -> str:
    """
    Chama modelo via OpenRouter (interface compatível com OpenAI).
    Levanta RuntimeError em qualquer falha — tratado pelo roteador.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY não encontrada no .env")

    logger.info(f"[ai_analyst] OpenRouter → modelo: {model}")

    response = requests.post(
        OPENROUTER_URL,
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


# ── chamada Ollama (fallback local) ─────────────────────────

def call_ollama(system_prompt: str, data_context: str, model: str) -> str:
    """
    Fallback local via Ollama.
    Import lazy — não quebra o startup se Ollama não estiver instalado.
    """
    logger.info(f"[ai_analyst] Ollama → modelo: {model}")
    try:
        import ollama as ollama_client
    except ImportError:
        raise RuntimeError(
            "Pacote 'ollama' não instalado. "
            "Execute: pip install ollama"
        )

    response = ollama_client.chat(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": data_context},
        ],
        options={"temperature": 0.1, "num_predict": 2000},
    )
    return response["message"]["content"]


# ── roteador de providers ────────────────────────────────────

def call_model(system_prompt: str, data_context: str) -> str:
    """
    Roteia chamada para o provider correto lido do .env.

    Hierarquia:
      1. Provider configurado em AI_PROVIDER
      2. Ollama local como fallback automático (se provider principal falhar)
    """
    provider = os.getenv("AI_PROVIDER", "openrouter").lower().strip()
    model    = os.getenv("AI_MODEL", "qwen/qwen3-8b:free").strip()

    logger.info(f"[ai_analyst] Provider: {provider} | Modelo: {model}")

    if provider == "openrouter":
        try:
            return call_openrouter(system_prompt, data_context, model)
        except Exception as e:
            fallback = os.getenv("OLLAMA_FALLBACK_MODEL", "llama3.1:8b").strip()
            logger.warning(f"[ai_analyst] OpenRouter falhou ({e}). Fallback → Ollama/{fallback}")
            return call_ollama(system_prompt, data_context, fallback)

    elif provider == "ollama":
        return call_ollama(system_prompt, data_context, model)

    else:
        raise ValueError(
            f"AI_PROVIDER inválido: '{provider}'. Use 'openrouter' ou 'ollama'."
        )


# ── parsear e validar resposta ───────────────────────────────

def parse_response(raw: str) -> dict:
    """
    Extrai JSON da resposta do LLM com múltiplas estratégias de fallback.
    Valida via Pydantic — retorna estrutura de erro se tudo falhar.

    Estratégias (ordem):
      1. Parse direto do texto limpo
      2. Extração de bloco ```json ... ```
      3. Regex para encontrar objeto JSON no texto
      4. Estrutura de erro padronizada
    """
    cleaned = raw.strip()

    # estratégia 1 — parse direto
    try:
        data = json.loads(cleaned)
        return _validate_output(data, raw)
    except json.JSONDecodeError:
        pass

    # estratégia 2 — bloco markdown
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", cleaned)
    if match:
        try:
            data = json.loads(match.group(1).strip())
            return _validate_output(data, raw)
        except json.JSONDecodeError:
            pass

    # estratégia 3 — regex para objeto JSON
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            data = json.loads(match.group())
            return _validate_output(data, raw)
        except json.JSONDecodeError:
            pass

    # estratégia 4 — falha total
    logger.error(f"[ai_analyst] Todas as estratégias de parse falharam. Raw:\n{raw[:400]}")
    return _error_output("Modelo retornou formato inválido — JSON não encontrado", raw)


def _validate_output(data: dict, raw: str) -> dict:
    """
    Valida dict contra AnalysisOutput via Pydantic.
    Em falha de validação: loga campos ausentes e retorna o dict parcial
    com campos obrigatórios preenchidos — pipeline não trava.
    """
    try:
        validated = AnalysisOutput(**data)
        return validated.model_dump()
    except ValidationError as e:
        logger.warning(
            f"[ai_analyst] Validação Pydantic falhou — {e.error_count()} erro(s). "
            f"Usando dados parciais."
        )
        # preenche campos obrigatórios ausentes sem descartar o restante
        data.setdefault("priority_level",    "INDETERMINADO")
        data.setdefault("executive_summary", "Resumo não gerado pelo modelo.")
        data.setdefault("findings",          [])
        data.setdefault("threat_hypotheses", [])
        data.setdefault("recommendations",   [])
        data["_validation_warnings"] = [str(err["msg"]) for err in e.errors()]
        return data


# ── salvar análise ───────────────────────────────────────────

def save_analysis(target: str, analysis: dict) -> str:
    """Persiste análise em JSON no diretório data/."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = OUTPUT_DIR / f"{target}_{timestamp}_ai_analysis.json"
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

    Parâmetros:
        collected_data  → output do collector  (WHOIS, DNS)         [obrigatório]
        validation      → output do validator  (score, checks)      [opcional]
        shodan_data     → output do shodan_agent (portas, serviços) [opcional]
        correlator_data → output do correlator  (pares, scores)     [opcional]

    Retorna:
        dict com análise estruturada — nunca levanta exceção.
    """
    target = collected_data.get("domain",
             collected_data.get("ip", "desconhecido"))
    logger.info(f"[ai_analyst] Iniciando análise para: {target}")

    # carrega skills e memória
    skills        = load_skills()
    memory        = load_memory()
    mem_str       = format_memory(memory)
    system_prompt = build_system_prompt(skills, mem_str)

    # monta contexto de dados
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
            "## DADOS SHODAN (infraestrutura exposta)",
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

    # chama o modelo — nunca propaga exceção para fora
    try:
        raw_response = call_model(system_prompt, data_context)
    except Exception as e:
        logger.error(f"[ai_analyst] Todos os providers falharam: {e}")
        analysis = _error_output(f"Todos os providers falharam: {e}")
        analysis["target"]      = target
        analysis["analyzed_at"] = datetime.now().isoformat()
        analysis["provider"]    = os.getenv("AI_PROVIDER", "openrouter")
        analysis["model"]       = os.getenv("AI_MODEL", "qwen/qwen3-8b:free")
        analysis["saved_to"]    = save_analysis(target, analysis)
        return analysis

    # parseia e valida resposta
    analysis = parse_response(raw_response)
    analysis["target"]      = target
    analysis["analyzed_at"] = datetime.now().isoformat()
    analysis["provider"]    = os.getenv("AI_PROVIDER", "openrouter")
    analysis["model"]       = os.getenv("AI_MODEL", "qwen/qwen3-8b:free")
    analysis["saved_to"]    = save_analysis(target, analysis)

    logger.info(
        f"[ai_analyst] Concluído — Provider: {analysis['provider']} | "
        f"Prioridade: {analysis.get('priority_level', '?')} | "
        f"Achados: {len(analysis.get('findings', []))}"
    )

    return analysis