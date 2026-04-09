"""
correlator.py — Análise de correlação entre múltiplos alvos coletados

Recebe lista de outputs do collector.py e compara todos os pares possíveis,
identificando infraestrutura compartilhada: IPs, name servers e registrars.
Funciona para domínios e IPs — extrai do schema padronizado do collector.
"""

from itertools import combinations


# ---------------------------------------------------------------------------
# Extratores de dados do schema do collector
# ---------------------------------------------------------------------------

def extract_ips(collected: dict) -> set:
    """
    Extrai todos os IPs do output do collector.
    Funciona para domínios (campo A) e para IPs (campo A = o próprio IP).
    """
    return set(collected.get("dns", {}).get("A", []))


def extract_nameservers(collected: dict) -> set:
    """
    Extrai name servers do WHOIS.
    IPs têm WHOIS skipped — retorna set vazio sem erro.
    Normaliza para minúsculo para comparação segura.
    """
    whois = collected.get("whois", {})

    # IPs têm whois com flag skipped — não tem name_servers
    if whois.get("skipped"):
        return set()

    ns = whois.get("name_servers", []) or []
    return set(n.lower() for n in ns)


def extract_registrar(collected: dict) -> str:
    """
    Extrai o registrar do WHOIS.
    Retorna string vazia para IPs (WHOIS skipped).
    """
    whois = collected.get("whois", {})

    if whois.get("skipped"):
        return ""

    return whois.get("registrar", "") or ""


def _get_label(collected: dict) -> str:
    """
    Retorna identificador legível do alvo — domínio ou IP.
    Usado nos campos 'pair' do resultado.
    """
    return collected.get("domain") or collected.get("ip") or "unknown"


# ---------------------------------------------------------------------------
# Lógica de correlação entre pares
# ---------------------------------------------------------------------------

def correlate_pair(a: dict, b: dict) -> dict:
    """
    Compara dois outputs do collector e calcula score de correlação.

    Pesos:
      - IP compartilhado:       50pts (correlação forte — mesma infra)
      - Name server comum:      30pts (correlação média — mesmo provedor DNS)
      - Mesmo registrar:        20pts (correlação fraca — coincidência comum)

    Score >= 50 indica correlação significativa.

    Args:
        a: Output do collector para o primeiro alvo.
        b: Output do collector para o segundo alvo.

    Returns:
        dict com score, pares, IPs e NS compartilhados.
    """
    label_a = _get_label(a)
    label_b = _get_label(b)

    ips_a = extract_ips(a)
    ips_b = extract_ips(b)
    shared_ips = ips_a & ips_b       # interseção de sets

    ns_a = extract_nameservers(a)
    ns_b = extract_nameservers(b)
    shared_ns = ns_a & ns_b

    registrar_a = extract_registrar(a)
    registrar_b = extract_registrar(b)
    same_registrar = registrar_a == registrar_b and registrar_a != ""

    score = 0
    if shared_ips:
        score += 50
    if shared_ns:
        score += 30
    if same_registrar:
        score += 20

    return {
        "pair": [label_a, label_b],
        "correlation_score": score,
        "shared_ips": list(shared_ips),
        "shared_nameservers": list(shared_ns),
        "same_registrar": same_registrar,
        "registrar": registrar_a if same_registrar else None,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(collected_list: list[dict]) -> list[dict]:
    """
    Recebe lista de outputs do collector e retorna todos os pares correlacionados.

    Usa itertools.combinations para comparar todos os pares sem repetição.
    Um batch de 10 alvos gera 45 pares — complexidade O(n²).

    Args:
        collected_list: Lista de dicts retornados por collector.run().

    Returns:
        Lista de dicts com correlações entre cada par de alvos.
    """
    if len(collected_list) < 2:
        print("[correlator] Mínimo de 2 alvos necessário para correlação.")
        return []

    results = []
    for a, b in combinations(collected_list, 2):
        pair_result = correlate_pair(a, b)
        results.append(pair_result)

        label = f"{pair_result['pair'][0]} <-> {pair_result['pair'][1]}"
        score = pair_result["correlation_score"]
        strength = "FORTE" if score >= 50 else ("MÉDIA" if score >= 30 else "FRACA")
        print(f"[correlator] {label} | score={score} | {strength}")

    return results