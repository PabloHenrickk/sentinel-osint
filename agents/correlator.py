from itertools import combinations


def extract_ips(collected: dict) -> set:
    """
    Extrai todos os IPs de um resultado coletado.
    """
    return set(collected.get("dns", {}).get("A", []))


def extract_nameservers(collected: dict) -> set:
    """
    Extrai name servers de um resultado coletado.
    Normaliza para minúsculo para comparação segura.
    """
    ns = collected.get("whois", {}).get("name_servers", []) or []
    return set(n.lower() for n in ns)


def extract_registrar(collected: dict) -> str:
    """
    Extrai o registrar do WHOIS.
    """
    return collected.get("whois", {}).get("registrar", "") or ""


def correlate_pair(a: dict, b: dict) -> dict:
    """
    Compara dois resultados coletados e encontra pontos em comum.
    Retorna dicionário com as correlações encontradas.
    """
    domain_a = a.get("domain", "?")
    domain_b = b.get("domain", "?")

    ips_a = extract_ips(a)
    ips_b = extract_ips(b)
    shared_ips = ips_a & ips_b  # operador & = interseção entre sets

    ns_a = extract_nameservers(a)
    ns_b = extract_nameservers(b)
    shared_ns = ns_a & ns_b

    registrar_a = extract_registrar(a)
    registrar_b = extract_registrar(b)
    same_registrar = (
        registrar_a == registrar_b and registrar_a != ""
    )

    # calcula força da correlação
    score = 0
    if shared_ips:
        score += 50  # mesmo IP é correlação forte
    if shared_ns:
        score += 30  # mesmo name server é correlação média
    if same_registrar:
        score += 20  # mesmo registrar é correlação fraca

    return {
        "pair": [domain_a, domain_b],
        "correlation_score": score,
        "shared_ips": list(shared_ips),
        "shared_nameservers": list(shared_ns),
        "same_registrar": same_registrar,
        "registrar": registrar_a if same_registrar else None,
    }


def run(target: str) -> dict:
    """
    Coleta WHOIS e DNS para domínio, ou apenas DNS reverso para IP.
    Detecta automaticamente o tipo de alvo.
    """
    import re
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))

    print(f"[collector] Iniciando coleta para: {target} ({'IP' if is_ip else 'domínio'})")

    if is_ip:
        # IPs não têm WHOIS de domínio — coleta só o que faz sentido
        result = {
            "ip"        : target,
            "domain"    : None,
            "target_type": "ip",
            "timestamp" : datetime.now().isoformat(),
            "whois"     : {"skipped": "Alvo é IP — WHOIS de domínio não aplicável"},
            "dns"       : collect_dns_reverse(target),
        }
    else:
        result = {
            "domain"    : target,
            "ip"        : None,
            "target_type": "domain",
            "timestamp" : datetime.now().isoformat(),
            "whois"     : collect_whois(target),
            "dns"       : collect_dns(target),
        }

    filepath = save_output(target.replace(".", "_"), result)
    print(f"[collector] Resultado salvo em: {filepath}")
    return result