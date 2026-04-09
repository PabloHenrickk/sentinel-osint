"""
validator.py — Avalia qualidade dos dados coletados e atribui score 0-100.

Lógica de scoring separada por tipo de alvo:
  - Domínios: formato (20pts) + WHOIS (40pts) + DNS/A (40pts)
  - IPs: PTR presente (60pts) + A confirmado (40pts)
    → WHOIS e formato de domínio não são checados nem pontuados para IPs.
"""

import re

# Regex para validar formato de domínio
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# Score mínimo para aprovação no pipeline
APPROVAL_THRESHOLD = 70


# ---------------------------------------------------------------------------
# Validações individuais
# ---------------------------------------------------------------------------

def validate_domain_format(domain: str) -> dict:
    """
    Verifica se o domínio tem formato válido.
    Nunca chamada para IPs — usaria regex em endereço IP e aprovaria errado.
    """
    is_valid = bool(DOMAIN_PATTERN.match(domain))
    return {
        "valid": is_valid,
        "score": 20 if is_valid else 0,
        "reason": None if is_valid else "Formato de domínio inválido",
    }


def validate_whois(whois_data: dict) -> dict:
    """
    Verifica se o WHOIS retornou dados úteis para domínios.
    Nunca chamada para IPs — whois.skipped=True indica que não se aplica.
    """
    if "error" in whois_data:
        return {"valid": False, "score": 0, "reason": whois_data["error"]}

    required_fields = ["registrar", "creation_date"]
    missing = [f for f in required_fields if not whois_data.get(f)]

    if missing:
        return {"valid": False, "score": 0, "reason": f"Campos ausentes: {missing}"}

    return {"valid": True, "score": 40, "reason": None}


def validate_dns_domain(dns_data: dict) -> dict:
    """
    Para domínios: verifica se resolveu pelo menos um registro A.
    Score: 40pts se tem A, 0pts se não tem.
    """
    a_records = dns_data.get("A", [])
    if not a_records:
        return {"valid": False, "score": 0, "reason": "Nenhum registro A encontrado"}
    return {"valid": True, "score": 40, "reason": None}


def validate_dns_ip(dns_data: dict) -> dict:
    """
    Para IPs: checa PTR (reverse DNS real) e confirma A (o próprio IP).

    Pesos:
      - A confirmado:  40pts (o IP existe e foi coletado)
      - PTR presente:  60pts (reverse DNS configurado — mais contexto)
      - PTR ausente:   0pts de bônus (normal em CDNs e clouds — não penaliza)

    Score máximo: 100. Score mínimo: 40 (IP sem PTR ainda é válido).
    """
    a_records = dns_data.get("A", [])
    ptr_records = dns_data.get("PTR", [])

    score = 0
    reasons = []

    if a_records:
        score += 40
    else:
        reasons.append("IP não encontrado no campo A")

    if ptr_records:
        score += 60
    else:
        reasons.append("PTR ausente — reverse DNS não configurado (comum em CDNs)")

    return {
        "valid": score >= 40,   # aprovado se ao menos o IP está confirmado
        "score": score,
        "ptr_records": ptr_records,
        "reason": "; ".join(reasons) if reasons else None,
    }


# ---------------------------------------------------------------------------
# Score final
# ---------------------------------------------------------------------------

def calculate_confidence(checks: dict, is_ip: bool) -> int:
    """
    Soma os scores das verificações aplicáveis ao tipo de alvo.

    Para domínios: domain_format + whois + dns = máx 100
    Para IPs: dns_ip = máx 100 (PTR 60 + A 40)
    """
    if is_ip:
        return checks["dns"]["score"]

    return (
        checks["domain_format"]["score"]
        + checks["whois"]["score"]
        + checks["dns"]["score"]
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(collected_data: dict) -> dict:
    """
    Valida dados do collector e atribui score de confiança.

    Lê o flag `is_ip` do collector para aplicar critérios corretos.
    O campo `target` no output contém domínio ou IP — nunca mistura os dois.

    Args:
        collected_data: dict retornado por collector.run().

    Returns:
        dict com score, status de aprovação e breakdown por checagem.
    """
    is_ip: bool = collected_data.get("is_ip", False)
    target: str = collected_data.get("ip") if is_ip else collected_data.get("domain", "")
    dns_data: dict = collected_data.get("dns", {})
    whois_data: dict = collected_data.get("whois", {})

    print(f"[validator] Validando: {target} (tipo: {'IP' if is_ip else 'domínio'})")

    if is_ip:
        checks = {
            "domain_format": {"valid": True,  "score": 0, "reason": "N/A para IPs"},
            "whois":         {"valid": True,  "score": 0, "reason": "N/A para IPs"},
            "dns":           validate_dns_ip(dns_data),
        }
    else:
        checks = {
            "domain_format": validate_domain_format(target),
            "whois":         validate_whois(whois_data),
            "dns":           validate_dns_domain(dns_data),
        }

    confidence = calculate_confidence(checks, is_ip)
    approved = confidence >= APPROVAL_THRESHOLD

    validation = {
        "target":           target,           # domínio ou IP — nunca mistura
        "is_ip":            is_ip,            # propaga flag para agentes downstream
        "target_type":      "ip" if is_ip else "domain",
        "confidence_score": confidence,
        "approved":         approved,
        "checks":           checks,
    }

    status = "APROVADO" if approved else "REPROVADO"
    print(f"[validator] {status} — confiança: {confidence}/100")
    return validation