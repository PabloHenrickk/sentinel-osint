"""
infra_provider.py — Infrastructure Intelligence Provider

Fontes integradas:
  1. Shodan InternetDB (gratuito, sem key) — portas, CVEs, tags, hostnames
  2. IPInfo.io (50k req/mês grátis)        — ASN, CIDR, org, tipo, país
  3. BGPView API (gratuita, sem key)        — prefixos anunciados, peers, bloco CIDR completo

Pipeline de valor:
  IP → ASN → CIDR block completo → todos os prefixos da organização
  Isso transforma "analisei um IP" em "mapeei a infraestrutura da org".

Rate limits:
  - Shodan InternetDB: sem limite documentado (uso razoável)
  - IPInfo: 50.000 req/mês (plano free)
  - BGPView: sem limite documentado (uso razoável)
"""

from __future__ import annotations

import os
import ipaddress
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from providers.base import NormalizedEntity, ProviderResult

logger = logging.getLogger(__name__)

# ── Configuração ─────────────────────────────────────────────────────────────

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")  # opcional — aumenta rate limit

TIMEOUT = 12

_session = requests.Session()
_adapter = HTTPAdapter(
    max_retries=Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
)
_session.mount("https://", _adapter)


# ── Validação de IP ───────────────────────────────────────────────────────────

def _is_valid_public_ip(ip: str) -> bool:
    """
    Retorna True apenas para IPs públicos e roteáveis.
    Rejeita: privados (192.168.x, 10.x, 172.16-31.x),
             loopback (127.x), link-local (169.254.x), multicast.
    """
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except ValueError:
        return False


# ── Shodan InternetDB ─────────────────────────────────────────────────────────

def _fetch_shodan(ip: str) -> dict | None:
    """
    Shodan InternetDB: dados de reconhecimento passivo sem API key.
    Retorna portas abertas, CVEs conhecidos, tags e hostnames.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = _session.get(url, timeout=TIMEOUT)
        if resp.status_code == 404:
            logger.info("Shodan: IP %s sem dados indexados", ip)
            return {}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logger.warning("Shodan InternetDB falhou para %s: %s", ip, e)
        return None


def _normalize_shodan(raw: dict, ip: str) -> list[NormalizedEntity]:
    """
    Converte resposta do Shodan em NormalizedEntity por categoria.
    Separa: portas abertas, CVEs, hostnames — cada um é uma entidade.
    """
    entities: list[NormalizedEntity] = []

    # Portas abertas — uma entidade agregada
    ports: list[int] = raw.get("ports", [])
    if ports:
        entities.append(NormalizedEntity(
            entity=ip,
            source="shodan_internetdb",
            data_type="open_ports",
            value=",".join(str(p) for p in sorted(ports)),
            metadata={
                "count": len(ports),
                "tags": raw.get("tags", []),
                "hostnames": raw.get("hostnames", []),
                "vulns": raw.get("vulns", []),
            },
            confidence=0.90,
        ))

    # CVEs — uma entidade por CVE (permite indexar no grafo por severidade)
    for cve in raw.get("vulns", []):
        entities.append(NormalizedEntity(
            entity=ip,
            source="shodan_internetdb",
            data_type="cve",
            value=cve,
            metadata={"ip": ip, "detected_by": "shodan_passive"},
            confidence=0.75,  # CVE detectado passivamente — confirmar com scanner
        ))

    # Hostnames — permite correlação reversa (qual domínio usa este IP)
    for hostname in raw.get("hostnames", []):
        entities.append(NormalizedEntity(
            entity=ip,
            source="shodan_internetdb",
            data_type="hostname_reverso",
            value=hostname,
            metadata={"ip": ip},
            confidence=0.85,
        ))

    return entities


# ── IPInfo ────────────────────────────────────────────────────────────────────

def _fetch_ipinfo(ip: str) -> dict | None:
    """
    IPInfo: ASN, organização, país, tipo de hospedagem, CIDR.
    Com token: 50k req/mês. Sem token: ~1k req/dia.
    """
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
    try:
        resp = _session.get(url, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logger.warning("IPInfo falhou para %s: %s", ip, e)
        return None


def _normalize_ipinfo(raw: dict, ip: str) -> list[NormalizedEntity]:
    """
    ASN e contexto geográfico/organizacional como entidades separadas.
    O ASN é o dado mais valioso — habilita o BGPView pivot.
    """
    entities: list[NormalizedEntity] = []

    asn_raw: str = raw.get("org", "")          # ex: "AS15169 Google LLC"
    asn_number = ""
    asn_name   = ""

    if asn_raw and asn_raw.startswith("AS"):
        parts      = asn_raw.split(" ", 1)
        asn_number = parts[0]                  # "AS15169"
        asn_name   = parts[1] if len(parts) > 1 else ""

    if asn_number:
        entities.append(NormalizedEntity(
            entity=ip,
            source="ipinfo",
            data_type="asn",
            value=asn_number,
            metadata={
                "org_name":  asn_name,
                "country":   raw.get("country", ""),
                "city":      raw.get("city", ""),
                "region":    raw.get("region", ""),
                "cidr":      raw.get("network", ""),    # ex: "8.8.8.0/24"
                "hostname":  raw.get("hostname", ""),
                "timezone":  raw.get("timezone", ""),
            },
            confidence=0.92,
        ))

    # Tipo de hospedagem — dado crítico para contexto
    # "hosting": True → datacenter. False → residencial/mobile.
    privacy = raw.get("privacy", {})
    if privacy:
        entities.append(NormalizedEntity(
            entity=ip,
            source="ipinfo",
            data_type="ip_privacy_context",
            value=ip,
            metadata={
                "vpn":      privacy.get("vpn", False),
                "proxy":    privacy.get("proxy", False),
                "tor":      privacy.get("tor", False),
                "hosting":  privacy.get("hosting", False),
                "relay":    privacy.get("relay", False),
                "service":  privacy.get("service", ""),
            },
            confidence=0.88,
        ))

    return entities, asn_number  # retorna ASN para o BGPView pivot


# ── BGPView ───────────────────────────────────────────────────────────────────

def _fetch_bgpview_asn(asn: str) -> dict | None:
    """
    BGPView: dado um ASN, retorna todos os prefixos IPv4 anunciados.
    ASN pode ser "AS15169" ou "15169" — normalizamos aqui.
    """
    asn_clean = asn.lstrip("ASas")  # "AS15169" → "15169"
    url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
    try:
        resp = _session.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "ok":
            return data.get("data", {})
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("BGPView falhou para ASN %s: %s", asn, e)
        return None


def _normalize_bgpview(raw: dict, asn: str, ip: str) -> list[NormalizedEntity]:
    """
    Prefixos IPv4 do ASN → NormalizedEntity por bloco CIDR.

    Por que separar cada prefixo:
      Cada CIDR é um bloco de IPs que a organização controla.
      O grafo pode cruzar: "este IP de outro alvo está neste CIDR → mesma org?"
    """
    entities: list[NormalizedEntity] = []
    ipv4_prefixes: list[dict] = raw.get("ipv4_prefixes", [])

    for prefix in ipv4_prefixes:
        cidr   = prefix.get("prefix", "")
        name   = prefix.get("name", "")
        descr  = prefix.get("description", "")
        parent = prefix.get("parent", {}).get("prefix", "")

        if not cidr:
            continue

        entities.append(NormalizedEntity(
            entity=asn,
            source="bgpview",
            data_type="cidr_block",
            value=cidr,
            metadata={
                "asn":         asn,
                "name":        name,
                "description": descr,
                "parent_cidr": parent,
                "origin_ip":   ip,    # IP que levou a este ASN
            },
            confidence=0.93,
        ))

    logger.info(
        "BGPView: ASN %s anuncia %d prefixos IPv4", asn, len(ipv4_prefixes)
    )
    return entities


# ── Entry point público ───────────────────────────────────────────────────────

def query_infra(ip: str) -> ProviderResult:
    """
    Pipeline completo de infraestrutura para um IP.

    Fluxo:
      IP → Shodan (portas/CVEs) → IPInfo (ASN/contexto) → BGPView (CIDR block)

    O ASN retornado pelo IPInfo alimenta o BGPView automaticamente.
    Se IPInfo falhar, BGPView não é chamado (sem ASN para pivotar).

    Args:
        ip: Endereço IPv4 público. IPs privados são rejeitados.

    Returns:
        ProviderResult com todas as entidades coletadas e metadata de execução.
    """
    entities: list[NormalizedEntity] = []
    errors:   list[str]              = []
    metadata: dict[str, Any]         = {
        "ip": ip,
        "shodan_ports": 0,
        "cves_found": 0,
        "asn": "",
        "cidr_blocks": 0,
        "is_hosting": None,
        "is_vpn": None,
    }

    # Validação antes de qualquer requisição
    if not _is_valid_public_ip(ip):
        return ProviderResult(
            provider="infra_provider",
            target=ip,
            entities=[],
            errors=[f"IP inválido ou privado: {ip}"],
            metadata=metadata,
        )

    # ── 1. Shodan InternetDB ──────────────────────────────────────────────────
    try:
        shodan_raw = _fetch_shodan(ip)
        if shodan_raw:
            shodan_entities = _normalize_shodan(shodan_raw, ip)
            entities.extend(shodan_entities)

            # Atualiza metadata de resumo
            ports_entity = next(
                (e for e in shodan_entities if e.data_type == "open_ports"), None
            )
            cve_entities = [e for e in shodan_entities if e.data_type == "cve"]

            if ports_entity:
                metadata["shodan_ports"] = ports_entity.metadata.get("count", 0)
            metadata["cves_found"] = len(cve_entities)
    except Exception as e:
        errors.append(f"shodan: {e}")

    # ── 2. IPInfo (ASN + contexto) ────────────────────────────────────────────
    asn_number = ""
    try:
        ipinfo_raw = _fetch_ipinfo(ip)
        if ipinfo_raw:
            ipinfo_entities, asn_number = _normalize_ipinfo(ipinfo_raw, ip)
            entities.extend(ipinfo_entities)
            metadata["asn"] = asn_number

            # Extrai flags de privacidade para o metadata de resumo
            privacy_entity = next(
                (e for e in ipinfo_entities if e.data_type == "ip_privacy_context"),
                None,
            )
            if privacy_entity:
                metadata["is_hosting"] = privacy_entity.metadata.get("hosting")
                metadata["is_vpn"]     = privacy_entity.metadata.get("vpn")
    except Exception as e:
        errors.append(f"ipinfo: {e}")

    # ── 3. BGPView (CIDR block da organização) ────────────────────────────────
    # Só executa se temos ASN — sem ASN não há pivô possível
    if asn_number:
        try:
            bgp_raw = _fetch_bgpview_asn(asn_number)
            if bgp_raw:
                bgp_entities = _normalize_bgpview(bgp_raw, asn_number, ip)
                entities.extend(bgp_entities)
                metadata["cidr_blocks"] = len(
                    [e for e in bgp_entities if e.data_type == "cidr_block"]
                )
        except Exception as e:
            errors.append(f"bgpview: {e}")
    else:
        logger.info("infra_provider: ASN não disponível — BGPView ignorado para %s", ip)

    return ProviderResult(
        provider="infra_provider",
        target=ip,
        entities=entities,
        errors=errors,
        metadata=metadata,
    )