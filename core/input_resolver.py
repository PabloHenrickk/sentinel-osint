"""
input_resolver.py — Dispatcher de entrada do Sentinel OSINT

Detecta o tipo de qualquer input e normaliza para o formato esperado pelo pipeline.
Chamado em main.py antes do collector — determina o fluxo de cada alvo.

Tipos suportados:
    domain  → pipeline padrão
    ip      → direto ao infra_agent (pula collector de WHOIS)
    url     → extrai domínio → pipeline padrão
    email   → extrai domínio → pipeline + valida MX
    cnpj    → gov_agent → resolve domínio → pipeline
    asn     → expande bloco de IPs → pipeline em massa
"""

import re
from typing import Optional


# ── Patterns de detecção ──────────────────────────────────────────────────

_RE_IPV4  = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_IPV6  = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_RE_CNPJ  = re.compile(r"^\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}$|^\d{14}$")
_RE_ASN   = re.compile(r"^AS\d+$", re.IGNORECASE)
_RE_URL   = re.compile(r"^https?://", re.IGNORECASE)
_RE_EMAIL = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def detect_input_type(raw: str) -> str:
    """
    Detecta o tipo de input pelo formato da string.
    Ordem importa: URL e email antes de domain para evitar falso positivo.

    Returns:
        "url" | "email" | "cnpj" | "asn" | "ip" | "domain"
    """
    s = raw.strip()

    if _RE_URL.match(s):
        return "url"
    if _RE_EMAIL.match(s):
        return "email"
    if _RE_CNPJ.match(s):
        return "cnpj"
    if _RE_ASN.match(s):
        return "asn"
    if _RE_IPV4.match(s) or _RE_IPV6.match(s):
        return "ip"
    return "domain"


def normalize(raw: str) -> dict:
    """
    Normaliza qualquer input para o formato padrão do pipeline.

    Args:
        raw: string digitada pelo usuário — qualquer formato

    Returns:
        dict com:
            target          → string que o pipeline vai processar
            target_type     → tipo final após resolução
            original_type   → tipo como detectado antes da transformação
            original        → input exato do usuário
            metadata        → dados extras (CNPJ formatado, e-mail original, etc.)
            requires_gov_agent  → True se precisar de gov_agent para resolver
            requires_asn_expansion → True se precisar expandir bloco ASN
            routing_note    → string explicando o roteamento para o banner
    """
    s            = raw.strip()
    input_type   = detect_input_type(s)

    result: dict = {
        "original":               s,
        "original_type":          input_type,
        "target_type":            input_type,
        "metadata":               {},
        "requires_gov_agent":     False,
        "requires_asn_expansion": False,
        "routing_note":           "",
    }

    if input_type == "url":
        # Extrai domínio — remove schema, path, query, fragment
        domain = re.sub(r"^https?://", "", s, flags=re.IGNORECASE)
        domain = domain.split("/")[0].split("?")[0].split("#")[0]
        result["target"]       = domain
        result["target_type"]  = "domain"
        result["metadata"]["original_url"] = s
        result["routing_note"] = f"URL → domínio extraído: {domain}"

    elif input_type == "email":
        domain = s.split("@")[1]
        result["target"]       = domain
        result["target_type"]  = "domain"
        result["metadata"]["email"] = s
        result["metadata"]["note"]  = "domínio extraído do e-mail — pipeline padrão + validação MX"
        result["routing_note"] = f"E-mail → domínio: {domain}"

    elif input_type == "cnpj":
        cnpj_clean = re.sub(r"\D", "", s)
        formatted  = (
            f"{cnpj_clean[:2]}.{cnpj_clean[2:5]}.{cnpj_clean[5:8]}/"
            f"{cnpj_clean[8:12]}-{cnpj_clean[12:14]}"
        )
        result["target"]                  = cnpj_clean
        result["metadata"]["cnpj_formatted"] = formatted
        result["metadata"]["note"]        = "gov_agent resolverá CNPJ → domínio → pipeline"
        result["requires_gov_agent"]      = True
        result["routing_note"]            = f"CNPJ {formatted} → gov_agent"

    elif input_type == "asn":
        result["target"]                  = s.upper()
        result["metadata"]["note"]        = "expansão de bloco de IPs via BGP"
        result["requires_asn_expansion"]  = True
        result["routing_note"]            = f"ASN {s.upper()} → expansão de bloco"

    else:
        # ip ou domain — passa direto, sem transformação
        result["target"]       = s
        result["routing_note"] = (
            f"IP direto: {s}" if input_type == "ip" else f"Domínio: {s}"
        )

    return result


def normalize_batch(raws: list[str]) -> list[dict]:
    """
    Normaliza uma lista de inputs, útil para múltiplos alvos.

    Args:
        raws: lista de strings como digitadas pelo usuário

    Returns:
        lista de dicts normalizados — mesma estrutura de normalize()
    """
    return [normalize(r) for r in raws]