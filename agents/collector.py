"""
collector.py — Agente de reconhecimento passivo (WHOIS + DNS)

Detecta automaticamente se o alvo é IP ou domínio e aplica
a coleta correta para cada tipo. O flag `is_ip` no output
é consumido pelo validator para aplicar a lógica de score adequada.
"""

import re
import json
import os
from datetime import datetime

import whois
import dns.resolver
import dns.reversename

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.config import OUTPUT_DIR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_ip(target: str) -> bool:
    """Retorna True se o alvo for um IPv4 válido."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))


def _parse_date(value) -> str | None:
    """Normaliza datas que chegam como datetime, lista ou string."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")
    return str(value)


# ---------------------------------------------------------------------------
# Coleta WHOIS — apenas para domínios
# ---------------------------------------------------------------------------

def collect_whois(domain: str) -> dict:
    """
    Consulta WHOIS para um domínio.
    Nunca deve ser chamada para IPs — use o bloco is_ip em run().
    Retorna dict estruturado mesmo em falha.
    """
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": _parse_date(data.creation_date),
            "expiration_date": _parse_date(data.expiration_date),
            "updated_date": _parse_date(data.updated_date),
            "name_servers": (
                [ns.lower() for ns in data.name_servers]
                if isinstance(data.name_servers, list)
                else []
            ),
            "status": data.status if isinstance(data.status, list) else [data.status],
            "emails": data.emails if isinstance(data.emails, list) else (
                [data.emails] if data.emails else []
            ),
            "org": getattr(data, "org", None),
            "country": getattr(data, "country", None),
        }
    except Exception as e:
        return {"error": f"WHOIS falhou: {str(e)}"}


# ---------------------------------------------------------------------------
# Coleta DNS — domínios
# ---------------------------------------------------------------------------

def collect_dns(domain: str) -> dict:
    """
    Resolve registros DNS para domínios.
    Registros ausentes retornam lista vazia — nunca quebram o pipeline.
    """
    result = {}
    for record in ["A", "MX", "TXT", "NS", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, record)
            result[record] = [str(r) for r in answers]
        except Exception:
            result[record] = []
    return result


# ---------------------------------------------------------------------------
# Coleta DNS reverso — IPs
# ---------------------------------------------------------------------------

def collect_dns_reverse(ip: str) -> dict:
    """
    Para IPs: tenta resolução reversa (PTR).
    Retorna o próprio IP no campo A para manter schema consistente
    com o que o validator e correlator esperam.
    """
    result = {
        "A": [ip],   # IP já conhecido — mantém schema uniforme
        "PTR": [],
    }
    try:
        reversed_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reversed_name, "PTR")
        result["PTR"] = [str(r) for r in answers]
    except Exception:
        result["PTR"] = []  # sem PTR é normal — não penaliza
    return result


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------

def save_output(target: str, data: dict) -> str:
    """Salva resultado em JSON com timestamp no diretório de output."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.replace(".", "_")
    filename = f"{OUTPUT_DIR}/{safe_name}_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return filename


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(target: str) -> dict:
    """
    Coleta WHOIS + DNS para domínio, ou apenas DNS reverso para IP.
    Detecta automaticamente o tipo de alvo.

    O campo `is_ip` é obrigatório no output — o validator.py depende
    dele para aplicar a lógica de score correta sem penalizar IPs.

    Args:
        target: Domínio (ex: "example.com") ou IP (ex: "8.8.8.8").

    Returns:
        dict com schema padronizado consumido pelo validator.py.
    """
    target = target.strip().lower()
    is_ip = _is_ip(target)

    print(f"[collector] Iniciando coleta para: {target} ({'IP' if is_ip else 'domínio'})")

    if is_ip:
        result = {
            "domain": None,
            "ip": target,
            "is_ip": True,                    # flag que o validator precisa
            "target_type": "ip",
            "timestamp": datetime.now().isoformat(),
            "whois": {
                "skipped": True,              # flag booleana — não string
                "reason": "Alvo é IP — WHOIS de domínio não aplicável",
            },
            "dns": collect_dns_reverse(target),
        }
    else:
        result = {
            "domain": target,
            "ip": None,
            "is_ip": False,                   # flag que o validator precisa
            "target_type": "domain",
            "timestamp": datetime.now().isoformat(),
            "whois": collect_whois(target),
            "dns": collect_dns(target),
        }

    filepath = save_output(target, result)
    print(f"[collector] Resultado salvo em: {filepath}")
    return result