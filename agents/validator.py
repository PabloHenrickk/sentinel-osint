import re


# padrão regex para validar formato de domínio
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def validate_domain(domain: str) -> dict:
    """
    Verifica se o domínio tem formato válido.
    """
    is_valid = bool(DOMAIN_PATTERN.match(domain))
    return {
        "valid": is_valid,
        "reason": None if is_valid else "Formato de domínio inválido",
    }


def validate_whois(whois_data: dict) -> dict:
    """
    Verifica se o WHOIS retornou dados úteis.
    """
    # se veio com chave 'error', a coleta falhou
    if "error" in whois_data:
        return {"valid": False, "reason": whois_data["error"]}

    # campos mínimos que precisam existir
    required_fields = ["registrar", "creation_date"]
    missing = [f for f in required_fields if not whois_data.get(f)]

    if missing:
        return {"valid": False, "reason": f"Campos ausentes: {missing}"}

    return {"valid": True, "reason": None}


def validate_dns(dns_data: dict) -> dict:
    """
    Verifica se o DNS resolveu pelo menos um registro A (IP).
    """
    a_records = dns_data.get("A", [])

    if not a_records:
        return {"valid": False, "reason": "Nenhum registro A encontrado"}

    return {"valid": True, "reason": None}


def calculate_confidence(results: dict) -> int:
    """
    Calcula pontuação de confiança de 0 a 100.
    Cada verificação aprovada vale pontos.
    """
    score = 0

    if results["domain"]["valid"]:
        score += 30

    if results["whois"]["valid"]:
        score += 40

    if results["dns"]["valid"]:
        score += 30

    return score


def run(collected_data: dict) -> dict:
    """
    Valida dados do collector.
    Detecta automaticamente se é IP ou domínio e aplica critérios corretos.
    """
    target_type = collected_data.get("target_type", "domain")
    target      = collected_data.get("domain") or collected_data.get("ip", "")

    print(f"[validator] Validando: {target} (tipo: {target_type})")

    if target_type == "ip":
        results = {
            "domain": {"valid": True,  "reason": "Alvo é IP — validação de formato não aplicável"},
            "whois" : {"valid": True,  "reason": "Alvo é IP — WHOIS de domínio não aplicável"},
            "dns"   : validate_dns(collected_data.get("dns", {})),
        }
    else:
        results = {
            "domain": validate_domain(target),
            "whois" : validate_whois(collected_data.get("whois", {})),
            "dns"   : validate_dns(collected_data.get("dns", {})),
        }

    confidence = calculate_confidence(results)

    validation = {
        "domain"          : target,
        "target_type"     : target_type,
        "confidence_score": confidence,
        "approved"        : confidence >= 70,
        "checks"          : results,
    }

    status = "APROVADO" if validation["approved"] else "REPROVADO"
    print(f"[validator] {status} — confiança: {confidence}/100")
    return validation