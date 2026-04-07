import json
import os
import re
import requests
from datetime import datetime
from pathlib import Path

import ollama
from dotenv import load_dotenv

load_dotenv()

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger

logger = get_logger(__name__)

# ── caminhos ────────────────────────────────────────────────
SKILLS_DIR  = Path("core/skills")
MEMORY_DIR  = Path("core/memory")
OUTPUT_DIR  = Path("data")

SKILL_FILES = [
    "osint_analyst.md",
    "pentest_reasoning.md",
    "report_format.md",
]

MEMORY_FILES = {
    "patterns"    : MEMORY_DIR / "learned_patterns.json",
    "corrections" : MEMORY_DIR / "error_corrections.json",
}

# ── providers disponíveis ────────────────────────────────────
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


# ── carregamento de skills ───────────────────────────────────
def load_skills() -> str:
    content = []
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
def load_memory() -> dict:
    memory = {"patterns": [], "corrections": []}

    for key, path in MEMORY_FILES.items():
        if path.exists():
            try:
                data  = json.loads(path.read_text(encoding="utf-8"))
                items = data.get("corrections", []) if key == "corrections" \
                        else data.get("patterns", [])
                memory[key] = items
                logger.info(
                    f"[ai_analyst] Memória carregada: {key} "
                    f"({len(memory[key])} entradas)"
                )
            except Exception as e:
                logger.error(f"[ai_analyst] Erro ao ler memória {key}: {e}")

    return memory


def format_memory(memory: dict) -> str:
    lines = []

    if memory["corrections"]:
        lines.append("## CORREÇÕES APRENDIDAS (aplicar sempre)")
        for c in memory["corrections"]:
            lines.append(f"- {c.get('rule', '')}")

    if memory["patterns"]:
        lines.append("## PADRÕES CONHECIDOS")
        for p in memory["patterns"]:
            lines.append(f"- {p.get('pattern', '')}")

    return "\n".join(lines) if lines else ""


# ── salvar na memória ────────────────────────────────────────
def save_correction(rule: str, context: str = ""):
    path = MEMORY_FILES["corrections"]
    data = json.loads(path.read_text(encoding="utf-8"))

    correction = {
        "rule"      : rule,
        "context"   : context,
        "created_at": datetime.now().isoformat(),
    }

    if "corrections" not in data:
        data["corrections"] = []

    data["corrections"].append(correction)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    logger.info(f"[ai_analyst] Correção salva: {rule[:60]}...")


def save_pattern(pattern: str, source: str = ""):
    path = MEMORY_FILES["patterns"]
    data = json.loads(path.read_text(encoding="utf-8"))

    entry = {
        "pattern"   : pattern,
        "source"    : source,
        "created_at": datetime.now().isoformat(),
    }

    if "patterns" not in data:
        data["patterns"] = []

    data["patterns"].append(entry)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    logger.info(f"[ai_analyst] Padrão salvo: {pattern[:60]}...")


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
        parts.append("")
        parts.append("## MEMÓRIA ATIVA — aplicar em toda análise")
        parts.append(memory)

    return "\n".join(parts)


# ── chamada OpenRouter (Qwen3.6 Plus) ───────────────────────
def call_openrouter(system_prompt: str, data_context: str,
                    model: str) -> str:
    """
    Chama o modelo via OpenRouter.
    Compatível com a interface OpenAI — funciona com qualquer
    modelo disponível no OpenRouter.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY não encontrada no .env")

    logger.info(f"[ai_analyst] OpenRouter → modelo: {model}")

    response = requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization" : f"Bearer {api_key}",
            "Content-Type"  : "application/json",
            "HTTP-Referer"  : "https://github.com/PabloHenrickk/sentinel-osint",
            "X-Title"       : "Sentinel OSINT",
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
            f"OpenRouter retornou {response.status_code}: {response.text[:200]}"
        )

    return response.json()["choices"][0]["message"]["content"]


# ── chamada Ollama (fallback local) ─────────────────────────
def call_ollama(system_prompt: str, data_context: str,
                model: str) -> str:
    """
    Fallback local via Ollama.
    Usado quando OpenRouter não está disponível ou
    AI_PROVIDER=ollama no .env.
    """
    logger.info(f"[ai_analyst] Ollama → modelo: {model}")

    response = ollama.chat(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": data_context},
        ],
        options={
            "temperature": 0.1,
            "num_predict": 2000,
        }
    )

    return response["message"]["content"]


# ── roteador de providers ────────────────────────────────────
def call_model(system_prompt: str, data_context: str) -> str:
    """
    Roteia a chamada para o provider correto baseado no .env.
    Hierarquia:
      1. OpenRouter (Qwen3.6 Plus free) — provider padrão
      2. Ollama local — fallback automático
    """
    provider = os.getenv("AI_PROVIDER", "openrouter").lower()
    model    = os.getenv("AI_MODEL", "qwen/qwen3.6-plus:free")

    if provider == "openrouter":
        try:
            return call_openrouter(system_prompt, data_context, model)
        except Exception as e:
            logger.warning(
                f"[ai_analyst] OpenRouter falhou: {e}. "
                f"Tentando fallback Ollama..."
            )
            # fallback automático para Ollama
            fallback_model = os.getenv("OLLAMA_FALLBACK_MODEL", "llama3.1:8b")
            return call_ollama(system_prompt, data_context, fallback_model)

    elif provider == "ollama":
        return call_ollama(system_prompt, data_context, model)

    else:
        raise ValueError(
            f"AI_PROVIDER inválido: '{provider}'. "
            f"Use 'openrouter' ou 'ollama'."
        )


# ── parsear resposta ─────────────────────────────────────────
def parse_response(raw: str) -> dict:
    """
    Extrai e parseia o JSON da resposta do modelo.
    Tenta múltiplas estratégias antes de desistir.
    """
    cleaned = raw.strip()

    # remove bloco de código markdown se o modelo ignorou a instrução
    if "```" in cleaned:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", cleaned)
        if match:
            cleaned = match.group(1).strip()

    # tenta parsear direto
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # tenta encontrar o JSON dentro do texto
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # fallback estruturado
    logger.error(
        f"[ai_analyst] Falha ao parsear JSON. "
        f"Resposta bruta:\n{raw[:400]}"
    )
    return {
        "error"            : "Falha ao parsear resposta da IA",
        "raw_response"     : raw[:500],
        "priority_level"   : "INDETERMINADO",
        "executive_summary": "Análise falhou — modelo retornou formato inválido",
        "findings"         : [],
    }


# ── salvar relatório ─────────────────────────────────────────
def save_analysis(target: str, analysis: dict) -> str:
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = OUTPUT_DIR / f"{target}_{timestamp}_ai_analysis.json"

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)

    logger.info(f"[ai_analyst] Análise salva: {filename}")
    return str(filename)


# ── função principal ─────────────────────────────────────────
def run(collected_data: dict, validation: dict = None,
        shodan_data: dict = None) -> dict:
    """
    Função principal do AI Analyst.
    Recebe dados dos agentes anteriores e retorna inteligência estruturada.

    Parâmetros:
        collected_data → output do collector (WHOIS, DNS)
        validation     → output do validator (score, checks)
        shodan_data    → output do shodan_agent (portas, serviços)
    """
    target = collected_data.get("domain",
             collected_data.get("ip", "desconhecido"))
    logger.info(f"[ai_analyst] Iniciando análise para: {target}")

    # carrega skills e memória
    skills  = load_skills()
    memory  = load_memory()
    mem_str = format_memory(memory)

    # monta system prompt
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

    context_parts.append(
        "\nAnalise os dados acima e retorne JSON conforme o schema definido."
    )

    data_context = "\n".join(context_parts)

    # chama o modelo via provider configurado
    raw_response = call_model(system_prompt, data_context)

    # parseia resposta
    analysis = parse_response(raw_response)
    analysis["target"]      = target
    analysis["analyzed_at"] = datetime.now().isoformat()

    # registra qual provider foi usado
    analysis["provider"] = os.getenv("AI_PROVIDER", "openrouter")
    analysis["model"]    = os.getenv("AI_MODEL", "qwen/qwen3.6-plus:free")

    # salva análise
    filepath = save_analysis(target, analysis)
    analysis["saved_to"] = filepath

    # log do resultado
    priority = analysis.get("priority_level", "?")
    findings = len(analysis.get("findings", []))
    logger.info(
        f"[ai_analyst] Concluído — Provider: {analysis['provider']} | "
        f"Prioridade: {priority} | Achados: {findings}"
    )

    return analysis