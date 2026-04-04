import json
import os
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config import OUTPUT_DIR


def format_list(items: list) -> str:
    """
    Converte lista Python em lista Markdown.
    ['a', 'b'] → '- a\n- b'
    """
    if not items:
        return "- Nenhum dado encontrado"
    return "\n".join(f"- {item}" for item in items)


def generate_markdown(collected: dict, validation: dict) -> str:
    """
    Monta o relatório em Markdown com todos os dados coletados e validados.
    """
    domain = collected.get("domain", "desconhecido")
    timestamp = collected.get("timestamp", "")
    confidence = validation.get("confidence_score", 0)
    approved = validation.get("approved", False)
    status = "✅ Aprovado" if approved else "❌ Reprovado"

    whois = collected.get("whois", {})
    dns = collected.get("dns", {})

    # monta o documento linha por linha
    report = f"""# 🛡️ Relatório OSINT — {domain}

**Gerado em:** {timestamp}
**Status:** {status}
**Confiança:** {confidence}/100

---

## 📋 WHOIS

| Campo | Valor |
|---|---|
| Registrar | {whois.get('registrar', 'N/A')} |
| Criação | {whois.get('creation_date', 'N/A')} |
| Vencimento | {whois.get('expiration_date', 'N/A')} |

**Name Servers:**
{format_list(whois.get('name_servers', []))}

---

## 🌐 DNS

**Registros A (IPs):**
{format_list(dns.get('A', []))}

**Registros MX (E-mail):**
{format_list(dns.get('MX', []))}

**Registros TXT:**
{format_list(dns.get('TXT', []))}

---

## 🔍 Validação detalhada

| Verificação | Status | Motivo |
|---|---|---|
| Domínio | {'✅' if validation['checks']['domain']['valid'] else '❌'} | {validation['checks']['domain']['reason'] or 'OK'} |
| WHOIS | {'✅' if validation['checks']['whois']['valid'] else '❌'} | {validation['checks']['whois']['reason'] or 'OK'} |
| DNS | {'✅' if validation['checks']['dns']['valid'] else '❌'} | {validation['checks']['dns']['reason'] or 'OK'} |

---

*Gerado por Sentinel OSINT*
"""
    return report


def save_report(domain: str, markdown: str, data: dict) -> dict:
    """
    Salva relatório em Markdown e JSON.
    Retorna os caminhos dos arquivos gerados.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{OUTPUT_DIR}/{domain}_{timestamp}"

    # salva markdown
    md_path = f"{base}_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    # salva JSON completo
    json_path = f"{base}_full.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return {"markdown": md_path, "json": json_path}


def run(collected: dict, validation: dict) -> dict:
    """
    Função principal do reporter.
    Recebe dados do collector e do validator, gera relatório.
    """
    domain = collected.get("domain", "desconhecido")
    print(f"[reporter] Gerando relatório para: {domain}")

    markdown = generate_markdown(collected, validation)

    full_data = {
        "collected": collected,
        "validation": validation,
    }

    paths = save_report(domain, markdown, full_data)

    print(f"[reporter] Markdown: {paths['markdown']}")
    print(f"[reporter] JSON:     {paths['json']}")

    return paths