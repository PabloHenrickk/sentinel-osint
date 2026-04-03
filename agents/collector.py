import whois
import dns.resolver
import json
import os
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config import OUTPUT_DIR


def collect_whois(domain: str) -> dict:
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
        }
    except Exception as e:
        return {"error": f"WHOIS falhou: {str(e)}"}


def collect_dns(domain: str) -> dict:
    result = {}
    for record in ["A", "MX", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record)
            result[record] = [str(r) for r in answers]
        except Exception:
            result[record] = []
    return result


def save_output(domain: str, data: dict) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{OUTPUT_DIR}/{domain}_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filename


def run(domain: str) -> dict:
    print(f"[collector] Iniciando coleta para: {domain}")
    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "whois": collect_whois(domain),
        "dns": collect_dns(domain),
    }
    filepath = save_output(domain, result)
    print(f"[collector] Resultado salvo em: {filepath}")
    return result