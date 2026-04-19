"""
reputation_provider.py — IP & Domain Reputation Provider

Nome honesto: reputação, não breach. O que este provider entrega:
  - AbuseIPDB  → score de abuso 0–100, categorias de atividade maliciosa
  - VirusTotal → detecções por engine AV, categorias de ameaça
  - Censys     → serviços expostos com contexto de certificado (diferente do Shodan)

Rate limits (planos gratuitos):
  AbuseIPDB:  1.000 req/dia
  VirusTotal:   500 req/dia  (4 req/min)
  Censys:       250 req/mês  — usar com parcimônia, só quando relevante

Estratégia de uso:
  AbuseIPDB + VirusTotal rodam sempre.
  Censys só é chamado se AbuseIPDB score > 25 ou VirusTotal detections > 0.
  Isso preserva a cota mensal de 250 req para casos que realmente importam.
"""

from __future__ import annotations

import os
import time
import base64
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from providers.base import NormalizedEntity, ProviderResult

logger = logging.getLogger(__name__)

# ── Configuração ──────────────────────────────────────────────────────────────

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
CENSYS_ID      = os.getenv("CENSYS_API_ID", "")
CENSYS_SECRET  = os.getenv("CENSYS_API_SECRET", "")

TIMEOUT = 12

_session = requests.Session()
_session.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=3,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
    ),
)

# Mapa de categorias numéricas do AbuseIPDB → descrição legível
ABUSEIPDB_CATEGORIES: dict[int, str] = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def _fetch_abuseipdb(ip: str) -> dict | None:
    """Score de abuso e histórico de denúncias para um IP."""
    if not ABUSEIPDB_KEY:
        logger.warning("ABUSEIPDB_API_KEY não configurada")
        return None

    try:
        resp = _session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.exceptions.RequestException as e:
        logger.warning("AbuseIPDB falhou para %s: %s", ip, e)
        return None


def _normalize_abuseipdb(raw: dict, ip: str) -> NormalizedEntity:
    """
    Score de abuso → NormalizedEntity.

    O score 0–100 é o dado principal.
    Categorias numéricas são mapeadas para texto — o ai_analyst
    não deve precisar decodificar números para gerar hipóteses.
    """
    score      = raw.get("abuseConfidenceScore", 0)
    categories = raw.get("usageType", "")
    reports    = raw.get("totalReports", 0)
    last_seen  = raw.get("lastReportedAt", "")
    isp        = raw.get("isp", "")
    country    = raw.get("countryCode", "")

    # Converte lista de category IDs para descrições
    raw_categories: list[int] = raw.get("reports", [{}])[0].get("categories", []) if raw.get("reports") else []
    category_labels = [
        ABUSEIPDB_CATEGORIES.get(c, f"cat_{c}") for c in raw_categories
    ]

    # Confidence decresce com score baixo — dado pouco significativo
    confidence = 0.90 if score > 25 else 0.70

    return NormalizedEntity(
        entity=ip,
        source="abuseipdb",
        data_type="ip_reputation",
        value=str(score),
        metadata={
            "abuse_score":       score,
            "total_reports":     reports,
            "last_reported":     last_seen,
            "usage_type":        categories,
            "isp":               isp,
            "country":           country,
            "activity_types":    category_labels,
            "is_tor":            raw.get("isTor", False),
            "is_public":         raw.get("isPublic", True),
            "distinct_users":    raw.get("numDistinctUsers", 0),
        },
        confidence=confidence,
    )


# ── VirusTotal ────────────────────────────────────────────────────────────────

def _fetch_virustotal_ip(ip: str) -> dict | None:
    """Análise de reputação de IP no VirusTotal."""
    if not VIRUSTOTAL_KEY:
        logger.warning("VIRUSTOTAL_API_KEY não configurada")
        return None

    try:
        resp = _session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("attributes", {})
    except requests.exceptions.RequestException as e:
        logger.warning("VirusTotal falhou para %s: %s", ip, e)
        return None


def _fetch_virustotal_domain(domain: str) -> dict | None:
    """Análise de reputação de domínio no VirusTotal."""
    if not VIRUSTOTAL_KEY:
        return None

    # VirusTotal exige que domínios sejam passados sem codificação especial
    try:
        resp = _session.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("attributes", {})
    except requests.exceptions.RequestException as e:
        logger.warning("VirusTotal falhou para %s: %s", domain, e)
        return None


def _normalize_virustotal(raw: dict, target: str) -> NormalizedEntity:
    """
    Resultado do VirusTotal → NormalizedEntity.

    last_analysis_stats contém: malicious, suspicious, harmless, undetected.
    Confidence é proporcional ao número de engines que analisaram o target.
    """
    stats: dict = raw.get("last_analysis_stats", {})
    malicious    = stats.get("malicious", 0)
    suspicious   = stats.get("suspicious", 0)
    harmless     = stats.get("harmless", 0)
    undetected   = stats.get("undetected", 0)
    total        = malicious + suspicious + harmless + undetected

    reputation   = raw.get("reputation", 0)
    categories   = raw.get("categories", {})  # dict engine → categoria
    tags         = raw.get("tags", [])

    # Confidence baseada em cobertura de engines
    confidence = min(0.95, 0.60 + (total / 100) * 0.35) if total > 0 else 0.50

    return NormalizedEntity(
        entity=target,
        source="virustotal",
        data_type="vt_reputation",
        value=str(malicious),      # detecções maliciosas como valor principal
        metadata={
            "malicious":   malicious,
            "suspicious":  suspicious,
            "harmless":    harmless,
            "undetected":  undetected,
            "total_engines": total,
            "vt_reputation": reputation,
            "categories":  list(set(categories.values())),   # únicos
            "tags":        tags,
        },
        confidence=confidence,
    )


# ── Censys ────────────────────────────────────────────────────────────────────
CENSYS_TOKEN = os.getenv("CENSYS_API_KEY", "")

def _fetch_censys_ip(ip: str) -> dict | None:
    if not CENSYS_TOKEN:
        logger.info("CENSYS_API_KEY não configurada — Censys ignorado")
        return None
     time.sleep(2.5) #rate limit: 1 req/2.5s no free tier
     
    try:
        resp = _session.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            headers={
                "Authorization": f"Bearer {CENSYS_TOKEN}",
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("result", {})
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.info("Censys: IP %s sem dados", ip)
            return {}
        logger.warning("Censys falhou para %s: %s", ip, e)
        return None
    except requests.exceptions.RequestException as e:
        logger.warning("Censys falhou para %s: %s", ip, e)
        return None

def _normalize_censys(raw: dict, ip: str) -> NormalizedEntity | None:
    """
    Censys result → NormalizedEntity focado em certificados e serviços TLS.
    Retorna None se não há dados relevantes.
    """
    services: list[dict] = raw.get("services", [])
    if not services:
        return None

    # Extrai dados de TLS de serviços que têm certificado
    tls_services = []
    for svc in services:
        port     = svc.get("port")
        protocol = svc.get("transport_protocol", "")
        tls      = svc.get("tls", {})
        cert     = tls.get("certificates", {}).get("leaf_data", {})

        if cert:
            tls_services.append({
                "port":     port,
                "protocol": protocol,
                "subject":  cert.get("subject", {}),
                "issuer":   cert.get("issuer", {}),
                "expiry":   cert.get("not_after", ""),
                "names":    cert.get("names", []),
            })

    return NormalizedEntity(
        entity=ip,
        source="censys",
        data_type="censys_services",
        value=str(len(services)),
        metadata={
            "total_services":  len(services),
            "tls_services":    tls_services,
            "last_updated":    raw.get("last_updated_at", ""),
            "autonomous_system": raw.get("autonomous_system", {}),
        },
        confidence=0.90,
    )


# ── Entry point público ───────────────────────────────────────────────────────

def query_reputation(target: str, target_type: str = "ip") -> ProviderResult:
    """
    Pipeline de reputação para IP ou domínio.

    Estratégia de uso de cota:
      AbuseIPDB + VirusTotal sempre.
      Censys só se score AbuseIPDB > 25 ou VirusTotal detections > 0.

    Args:
        target:      IP ou domínio alvo.
        target_type: "ip" ou "domain". Define quais endpoints são chamados.

    Returns:
        ProviderResult com entidades de reputação e metadata de decisão.
    """
    entities: list[NormalizedEntity] = []
    errors:   list[str]              = []
    metadata: dict[str, Any]         = {
        "target":           target,
        "target_type":      target_type,
        "abuse_score":      0,
        "vt_detections":    0,
        "censys_called":    False,
        "high_risk":        False,
    }

    abuse_score   = 0
    vt_detections = 0

    # ── AbuseIPDB (apenas IPs) ────────────────────────────────────────────────
    if target_type == "ip":
        try:
            abuse_raw = _fetch_abuseipdb(target)
            if abuse_raw:
                entity = _normalize_abuseipdb(abuse_raw, target)
                entities.append(entity)
                abuse_score = int(entity.value)
                metadata["abuse_score"] = abuse_score
        except Exception as e:
            errors.append(f"abuseipdb: {e}")

    # ── VirusTotal (IP e domínio) ─────────────────────────────────────────────
    try:
        # Delay para respeitar limite de 4 req/min do VT free
        time.sleep(0.3)

        vt_raw = (
            _fetch_virustotal_ip(target)
            if target_type == "ip"
            else _fetch_virustotal_domain(target)
        )
        if vt_raw:
            entity = _normalize_virustotal(vt_raw, target)
            entities.append(entity)
            vt_detections = int(entity.value)
            metadata["vt_detections"] = vt_detections
    except Exception as e:
        errors.append(f"virustotal: {e}")

    # ── Censys (IP, condicional) ──────────────────────────────────────────────
    # Lógica de preservação de cota:
    # Censys tem 250 req/mês. Só gastamos se o target já mostrou sinal de risco.
    should_call_censys = (
        target_type == "ip"
        and (abuse_score > 25 or vt_detections > 0)
    )

    if should_call_censys:
        try:
            metadata["censys_called"] = True
            censys_raw = _fetch_censys_ip(target)
            if censys_raw:
                entity = _normalize_censys(censys_raw, target)
                if entity:
                    entities.append(entity)
        except Exception as e:
            errors.append(f"censys: {e}")

    # Flag de alto risco — usado pelo core/graph.py como multiplicador
    metadata["high_risk"] = abuse_score > 50 or vt_detections >= 3

    return ProviderResult(
        provider="reputation_provider",
        target=target,
        entities=entities,
        errors=errors,
        metadata=metadata,
    )