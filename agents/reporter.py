"""
reporter.py — Gerador de relatório base (Markdown + JSON)

Compatível com o schema atual do collector e validator:
  - collected["is_ip"]        → bool
  - collected["domain"]       → str | None
  - collected["ip"]           → str | None
  - collected["whois"]["skipped"] → True para IPs
  - validation["checks"]["domain_format"] → renomeado do antigo "domain"
"""

import json
import os
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config import OUTPUT_DIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def format_list(items: list) -> str:
    """['a', 'b'] → '- a\n- b'"""
    if not items:
        return "- Nenhum dado encontrado"
    return "\n".join(f"- {item}" for item in items)


def _get_target(collected: dict) -> str:
    """Retorna identificador do alvo — domínio ou IP, nunca None."""
    is_ip = collected.get("is_ip", False)
    if is_ip:
        return collected.get("ip") or "ip-desconhecido"
    return collected.get("domain") or "dominio-desconhecido"


def _safe_name(target: str) -> str:
    """Sanitiza target para uso em nome de arquivo."""
    return target.replace(".", "_").replace("/", "-").replace(":", "-")


# ---------------------------------------------------------------------------
# Seções do relatório
# ---------------------------------------------------------------------------

def _section_whois(collected: dict) -> str:
    """
    Seção WHOIS — exibe dados para domínios.
    Para IPs mostra aviso explicativo em vez de tabela vazia.
    """
    whois = collected.get("whois", {})

    if whois.get("skipped"):
        return """## 📋 WHOIS

> Alvo é um endereço IP — WHOIS de domínio não aplicável.
> Use os dados de infraestrutura (InternetDB/Shodan) para contexto de rede.
"""

    return f"""## 📋 WHOIS

| Campo | Valor |
|---|---|
| Registrar | {whois.get('registrar') or 'N/A'} |
| Criação | {whois.get('creation_date') or 'N/A'} |
| Vencimento | {whois.get('expiration_date') or 'N/A'} |
| Organização | {whois.get('org') or 'N/A'} |
| País | {whois.get('country') or 'N/A'} |

**Name Servers:**
{format_list(whois.get('name_servers', []))}
"""


def _section_dns(collected: dict) -> str:
    """
    Seção DNS — adapta labels conforme tipo de alvo.
    IPs exibem PTR em vez de A como registro principal.
    """
    dns    = collected.get("dns", {})
    is_ip  = collected.get("is_ip", False)

    if is_ip:
        return f"""## 🌐 DNS

**Reverse DNS (PTR):**
{format_list(dns.get('PTR', []))}

**IP confirmado:**
{format_list(dns.get('A', []))}
"""

    return f"""## 🌐 DNS

**Registros A (IPs):**
{format_list(dns.get('A', []))}

**Registros MX (E-mail):**
{format_list(dns.get('MX', []))}

**Registros TXT:**
{format_list(dns.get('TXT', []))}

**Name Servers (NS):**
{format_list(dns.get('NS', []))}
"""


def _section_validation(validation: dict) -> str:
    """
    Seção de validação — lê chaves do schema atual do validator.
    Suporta tanto 'domain_format' (novo) quanto 'domain' (legado).
    """
    checks = validation.get("checks", {})

    # suporte a schema novo (domain_format) e legado (domain)
    domain_check = checks.get("domain_format") or checks.get("domain", {})
    whois_check  = checks.get("whois", {})
    dns_check    = checks.get("dns", {})

    def icon(check: dict) -> str:
        return "✅" if check.get("valid") else "❌"

    def reason(check: dict) -> str:
        return check.get("reason") or "OK"

    return f"""## 🔍 Validação detalhada

| Verificação | Status | Observação |
|---|---|---|
| Formato | {icon(domain_check)} | {reason(domain_check)} |
| WHOIS | {icon(whois_check)} | {reason(whois_check)} |
| DNS | {icon(dns_check)} | {reason(dns_check)} |
"""


# ---------------------------------------------------------------------------
# Geração do relatório completo
# ---------------------------------------------------------------------------

def generate_markdown(collected: dict, validation: dict) -> str:
    """
    Monta relatório Markdown completo adaptado ao tipo de alvo.
    """
    target     = _get_target(collected)
    is_ip      = collected.get("is_ip", False)
    timestamp  = collected.get("timestamp", datetime.now().isoformat())
    confidence = validation.get("confidence_score", 0)
    approved   = validation.get("approved", False)
    status     = "✅ Aprovado" if approved else "❌ Reprovado"
    tipo       = "IP" if is_ip else "Domínio"

    return f"""# 🛡️ Relatório OSINT — {target}

**Tipo:** {tipo}
**Gerado em:** {timestamp}
**Status:** {status}
**Confiança:** {confidence}/100

---

{_section_whois(collected)}

---

{_section_dns(collected)}

---

{_section_validation(validation)}

---

*Gerado por Sentinel OSINT*
"""


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------

def save_report(target: str, markdown: str, data: dict) -> dict:
    """Salva relatório em Markdown e JSON. Retorna caminhos gerados."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe       = _safe_name(target)
    base       = f"{OUTPUT_DIR}/{safe}_{timestamp}"

    md_path   = f"{base}_report.md"
    json_path = f"{base}_full.json"

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return {"markdown": md_path, "json": json_path}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(collected: dict, validation: dict) -> dict:
    """
    Gera relatório base para domínio ou IP.
    Nunca levanta exceção — erros retornam dict com chave 'error'.
    """
    target = _get_target(collected)
    print(f"[reporter] Gerando relatório para: {target}")

    try:
        markdown = generate_markdown(collected, validation)
        full_data = {"collected": collected, "validation": validation}
        paths = save_report(target, markdown, full_data)

        print(f"[reporter] Markdown: {paths['markdown']}")
        print(f"[reporter] JSON:     {paths['json']}")
        return paths

    except Exception as e:
        print(f"[reporter] Erro ao gerar relatório: {e}")
        return {"error": str(e)}