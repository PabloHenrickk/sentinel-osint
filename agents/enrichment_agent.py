"""
enrichment_agent.py — Enriquecimento de inteligência do Sentinel OSINT

Agrega dados que o collector e infra_agent não capturam:
  - Subdomínios via crt.sh (gratuito, sem key)
  - Shodan API real (banners, versões, CVEs, org, ASN)
  - Fingerprint HTTP (stack tecnológica via headers)
  - Reputação via VirusTotal
  - Score de abuso via AbuseIPDB
  - Geolocalização detalhada via IPInfo

Nunca trava o pipeline — cada fonte falha de forma independente.
Retorna dict padronizado consumido pelo ai_analyst.
"""

import os
import re
import json
import time
import socket
import ssl
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger
from core.retry import with_retry

load_dotenv()
logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------------------

HTTP_TIMEOUT   = int(os.getenv("INFRA_HTTP_TIMEOUT", "10"))
SHODAN_KEY     = os.getenv("SHODAN_API_KEY", "")
VT_KEY         = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
IPINFO_TOKEN   = os.getenv("IPINFO_TOKEN", "")

# Máximo de CVEs enviados ao ai_analyst — 100 CVEs explodem o contexto do LLM.
# Os primeiros 15 são suficientes para o modelo entender o nível de exposição.
_MAX_CVES_FOR_LLM = 15

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8",
}


# ---------------------------------------------------------------------------
# Utilitários internos
# ---------------------------------------------------------------------------

def _mask_url(text: str) -> str:
    """
    Remove API keys de URLs e mensagens de erro antes de logar.
    Aplica regex sobre padrões de query string usados pelas APIs integradas.

    NUNCA deve ser chamada sobre dados que vão pro pipeline —
    apenas sobre strings destinadas exclusivamente a logs.
    """
    patterns = [
        r'([?&]key=)[^&\s"\']+',
        r'([?&]token=)[^&\s"\']+',
        r'([?&]api_key=)[^&\s"\']+',
        r'([?&]apikey=)[^&\s"\']+',
    ]
    for pattern in patterns:
        text = re.sub(pattern, r'\1***REDACTED***', text)
    return text


# ---------------------------------------------------------------------------
# 1. Subdomínios via crt.sh
# ---------------------------------------------------------------------------

def fetch_subdomains(domain: str) -> dict:
    """
    Consulta crt.sh (Certificate Transparency Logs) para encontrar
    subdomínios indexados em certificados TLS emitidos para o domínio.

    Por que é poderoso: cada subdomínio é um ponto de entrada potencial.
    dev.empresa.com, vpn.empresa.com, admin.empresa.com — tudo aparece aqui
    antes de aparecer em qualquer scan ativo.
    """
    logger.info(f"[enrichment] crt.sh → subdomínios de {domain}")
    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=HTTP_TIMEOUT,
            headers=_BROWSER_HEADERS,
        )
        response.raise_for_status()
        entries = response.json()

        subdomains: set[str] = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and not sub.startswith("*") and sub != domain:
                    subdomains.add(sub)

        result = sorted(subdomains)
        logger.info(f"[enrichment] crt.sh: {len(result)} subdomínio(s) encontrado(s)")
        return {
            "subdomains": result,
            "count": len(result),
            "source": "crt.sh",
        }

    except Exception as e:
        logger.warning(f"[enrichment] crt.sh falhou: {e}")
        return {"subdomains": [], "count": 0, "error": str(e)}


# ---------------------------------------------------------------------------
# 2. Shodan API real
# ---------------------------------------------------------------------------

def fetch_shodan_full(ip: str) -> dict:
    """
    Consulta Shodan API completa (não InternetDB).
    Com a key real você recebe banners, CVEs indexados, ASN, OS detectado.

    Diferença prática: InternetDB diz "porta 22 aberta".
    Shodan real diz "OpenSSH 7.4 — CVE-2018-15473 confirmado".
    """
    if not SHODAN_KEY:
        logger.warning("[enrichment] SHODAN_API_KEY não configurada — pulando Shodan completo")
        return {"error": "SHODAN_API_KEY não configurada", "skipped": True}

    logger.info(f"[enrichment] Shodan API → {ip}")
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=HTTP_TIMEOUT,
        )

        if response.status_code == 404:
            return {"error": "IP não indexado no Shodan", "ip": ip}

        if response.status_code == 401:
            return {"error": "SHODAN_API_KEY inválida ou expirada", "skipped": True}

        response.raise_for_status()
        data = response.json()

        # Shodan retorna lista em "data" — garante que é list antes de iterar
        raw_data = data.get("data", [])
        if not isinstance(raw_data, list):
            raw_data = []

        services = []
        for item in raw_data:
            if not isinstance(item, dict):
                continue
            port    = item.get("port")
            proto   = item.get("transport", "tcp")
            banner  = item.get("data", "").strip()[:300]
            product = item.get("product", "")
            version = item.get("version", "")
            cpes    = item.get("cpe", [])
            vulns   = list(item.get("vulns", {}).keys())

            services.append({
                "port"   : port,
                "proto"  : proto,
                "product": product,
                "version": version,
                "banner" : banner,
                "cpes"   : cpes,
                "cves"   : vulns,
            })

        # vulns no nível raiz pode ser dict ou list — normaliza para lista de strings
        raw_vulns = data.get("vulns", {})
        if isinstance(raw_vulns, dict):
            all_cves = list(raw_vulns.keys())
        elif isinstance(raw_vulns, list):
            all_cves = raw_vulns
        else:
            all_cves = []

        result = {
            "ip"          : ip,
            "org"         : data.get("org"),
            "isp"         : data.get("isp"),
            "asn"         : data.get("asn"),
            "country"     : data.get("country_name"),
            "city"        : data.get("city"),
            "os"          : data.get("os"),
            "open_ports"  : data.get("ports", []),
            "hostnames"   : data.get("hostnames", []),
            "services"    : services,
            "all_cves"    : all_cves,
            "last_update" : data.get("last_update"),
            "tags"        : data.get("tags", []),
            "source"      : "shodan_api",
        }

        logger.info(
            f"[enrichment] Shodan: {len(services)} serviço(s), "
            f"{len(all_cves)} CVE(s) em {ip}"
        )
        return result

    except Exception as e:
        logger.warning(f"[enrichment] Shodan API falhou para {ip}: {_mask_url(str(e))}")
        return {"error": "Shodan request falhou — ver logs internos", "ip": ip}


# ---------------------------------------------------------------------------
# 3. Fingerprint HTTP
# ---------------------------------------------------------------------------

def fetch_http_fingerprint(target: str) -> dict:
    """
    Analisa headers HTTP para identificar stack tecnológica sem scan ativo.
    Tenta HTTPS primeiro, fallback para HTTP.

    Por que importa: versão no header + CVE público = vetor direto.
    "Server: Apache/2.4.49" + CVE-2021-41773 = RCE sem autenticação.
    """
    logger.info(f"[enrichment] HTTP fingerprint → {target}")
    result: dict = {
        "target": target,
        "headers": {},
        "security": {},
        "tech_stack": [],
    }

    base = target if target.startswith("http") else f"https://{target}"

    try:
        response = requests.get(
            base,
            timeout=HTTP_TIMEOUT,
            headers=_BROWSER_HEADERS,
            allow_redirects=True,
            verify=False,
        )

        headers = dict(response.headers)
        result["status_code"]    = response.status_code
        result["final_url"]      = response.url
        result["headers"]        = {k.lower(): v for k, v in headers.items()}
        result["redirect_chain"] = [r.url for r in response.history]

        tech = []

        server = headers.get("Server", "")
        if server:
            tech.append(f"Server: {server}")
            result["server"] = server

        powered = headers.get("X-Powered-By", "")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
            result["powered_by"] = powered

        cdn_indicators = {
            "cf-ray"             : "Cloudflare",
            "x-amz-cf-id"        : "AWS CloudFront",
            "x-azure-ref"        : "Azure CDN",
            "x-cache"            : "Cache/CDN genérico",
            "x-fastly-request-id": "Fastly",
            "x-akamai-transformed": "Akamai",
        }
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header_key, cdn_name in cdn_indicators.items():
            if header_key in headers_lower:
                result["cdn"] = cdn_name
                tech.append(f"CDN: {cdn_name}")
                break

        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy"  : "CSP",
            "x-frame-options"          : "X-Frame-Options",
            "x-content-type-options"   : "X-Content-Type-Options",
            "permissions-policy"       : "Permissions-Policy",
            "referrer-policy"          : "Referrer-Policy",
        }
        security_status = {}
        for h, label in security_headers.items():
            present = h in headers_lower
            security_status[label] = {
                "present": present,
                "value"  : headers_lower.get(h),
            }
        result["security"] = security_status

        missing = [lbl for lbl, s in security_status.items() if not s["present"]]
        if missing:
            result["missing_security_headers"] = missing

        result["tech_stack"] = tech
        logger.info(f"[enrichment] HTTP fingerprint: {len(tech)} tecnologia(s) detectada(s)")

    except requests.exceptions.SSLError:
        try:
            base_http = base.replace("https://", "http://")
            resp2 = requests.get(base_http, timeout=HTTP_TIMEOUT, headers=_BROWSER_HEADERS)
            result["ssl_error"]   = True
            result["status_code"] = resp2.status_code
            result["note"]        = "HTTPS falhou — respondeu em HTTP sem TLS"
        except Exception as e2:
            result["error"] = f"HTTP e HTTPS falharam: {e2}"

    except Exception as e:
        logger.warning(f"[enrichment] HTTP fingerprint falhou para {target}: {e}")
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# 4. SSL/TLS
# ---------------------------------------------------------------------------

def fetch_ssl_info(target: str, port: int = 443) -> dict:
    """
    Extrai informações do certificado TLS diretamente.
    SANs revelam outros domínios da mesma infra sem nenhuma API.
    """
    logger.info(f"[enrichment] SSL/TLS → {target}:{port}")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()

        sans: list[str] = []
        for rtype, value in cert.get("subjectAltName", []):
            if rtype == "DNS":
                sans.append(value)

        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        result = {
            "subject"     : subject.get("commonName", ""),
            "issuer_org"  : issuer.get("organizationName", ""),
            "issuer_cn"   : issuer.get("commonName", ""),
            "sans"        : sans,
            "not_before"  : cert.get("notBefore", ""),
            "not_after"   : cert.get("notAfter", ""),
            "is_wildcard" : any("*" in s for s in sans),
            "san_count"   : len(sans),
        }

        try:
            from datetime import datetime, timezone
            expiry    = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
            expiry    = expiry.replace(tzinfo=timezone.utc)
            now       = datetime.now(timezone.utc)
            days_left = (expiry - now).days
            result["days_until_expiry"] = days_left
            result["expired"]           = days_left < 0
            result["expiring_soon"]     = 0 <= days_left <= 30
        except Exception:
            pass

        logger.info(
            f"[enrichment] SSL: {len(sans)} SAN(s) | "
            f"emissor: {result['issuer_org']} | "
            f"wildcard: {result['is_wildcard']}"
        )
        return result

    except Exception as e:
        logger.warning(f"[enrichment] SSL info falhou para {target}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# 5. VirusTotal
# ---------------------------------------------------------------------------

def fetch_virustotal(target: str) -> dict:
    """
    Consulta VirusTotal para reputação de domínio ou IP.
    500 req/dia no tier gratuito — usar com moderação.
    """
    if not VT_KEY:
        return {"error": "VIRUSTOTAL_API_KEY não configurada", "skipped": True}

    is_ip    = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    endpoint = (
        f"https://www.virustotal.com/api/v3/"
        f"{'ip_addresses' if is_ip else 'domains'}/{target}"
    )

    logger.info(f"[enrichment] VirusTotal → {target}")
    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": VT_KEY},
            timeout=HTTP_TIMEOUT,
        )

        if response.status_code == 404:
            return {"error": "Alvo não encontrado no VirusTotal", "target": target}

        response.raise_for_status()
        data  = response.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = {
            "target"        : target,
            "malicious"     : stats.get("malicious", 0),
            "suspicious"    : stats.get("suspicious", 0),
            "harmless"      : stats.get("harmless", 0),
            "undetected"    : stats.get("undetected", 0),
            "reputation"    : attrs.get("reputation", 0),
            "categories"    : attrs.get("categories", {}),
            "tags"          : attrs.get("tags", []),
            "last_analysis" : attrs.get("last_analysis_date", ""),
            "source"        : "virustotal",
        }

        total              = result["malicious"] + result["suspicious"]
        result["threat_score"] = total
        result["is_flagged"]   = total > 0

        logger.info(
            f"[enrichment] VirusTotal: {result['malicious']} malicioso(s), "
            f"{result['suspicious']} suspeito(s)"
        )
        return result

    except Exception as e:
        logger.warning(f"[enrichment] VirusTotal falhou para {target}: {e}")
        return {"error": str(e), "target": target}


# ---------------------------------------------------------------------------
# 6. AbuseIPDB
# ---------------------------------------------------------------------------

def fetch_abuseipdb(ip: str) -> dict:
    """
    Score 0-100 de abuso histórico do IP.
    Acima de 25: sinal de comprometimento ou abuso ativo.
    """
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_API_KEY não configurada", "skipped": True}

    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"skipped": True, "reason": "AbuseIPDB só para IPs"}

    logger.info(f"[enrichment] AbuseIPDB → {ip}")
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        result = {
            "ip"                : ip,
            "abuse_score"       : data.get("abuseConfidenceScore", 0),
            "total_reports"     : data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported"     : data.get("lastReportedAt", ""),
            "country"           : data.get("countryCode", ""),
            "isp"               : data.get("isp", ""),
            "domain"            : data.get("domain", ""),
            "is_tor"            : data.get("isTor", False),
            "is_public"         : data.get("isPublic", True),
            "usage_type"        : data.get("usageType", ""),
            "source"            : "abuseipdb",
        }
        result["is_abusive"] = result["abuse_score"] >= 25

        logger.info(
            f"[enrichment] AbuseIPDB: score {result['abuse_score']}/100, "
            f"{result['total_reports']} report(s)"
        )
        return result

    except Exception as e:
        logger.warning(f"[enrichment] AbuseIPDB falhou para {ip}: {e}")
        return {"error": str(e), "ip": ip}


# ---------------------------------------------------------------------------
# 7. IPInfo
# ---------------------------------------------------------------------------

def fetch_ipinfo(ip: str) -> dict:
    """
    Geolocalização e informações de rede do IP.
    50.000 req/mês no tier gratuito.
    """
    logger.info(f"[enrichment] IPInfo → {ip}")
    try:
        url    = f"https://ipinfo.io/{ip}/json"
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}

        response = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        return {
            "ip"      : ip,
            "hostname": data.get("hostname", ""),
            "org"     : data.get("org", ""),
            "asn"     : data.get("org", "").split()[0] if data.get("org") else "",
            "city"    : data.get("city", ""),
            "region"  : data.get("region", ""),
            "country" : data.get("country", ""),
            "loc"     : data.get("loc", ""),
            "timezone": data.get("timezone", ""),
            "source"  : "ipinfo",
        }

    except Exception as e:
        logger.warning(f"[enrichment] IPInfo falhou para {ip}: {_mask_url(str(e))}")
        return {"error": "IPInfo request falhou — ver logs internos", "ip": ip}


# ---------------------------------------------------------------------------
# Entry point principal
# ---------------------------------------------------------------------------

def run(
    collected_data: dict,
    ips: Optional[list[str]] = None,
    infra_data: Optional[dict] = None,
) -> dict:
    """
    Executa todas as fontes de enriquecimento de forma independente.
    Cada fonte falha isoladamente — uma API fora do ar não paralisa o resto.

    Args:
        collected_data: Output do collector (contém domain, ip, dns, whois).
        ips: Lista de IPs para consultas que exigem IP (Shodan, AbuseIPDB, IPInfo).
             Se None, tenta extrair do campo dns.A do collected_data.
        infra_data: Output do infra_agent — portas e CVEs do InternetDB/Shodan.
                    Sem isso, CVEs e portas não chegam ao ai_analyst.
    """
    is_ip  = collected_data.get("is_ip", False)
    target = collected_data.get("ip") if is_ip else collected_data.get("domain", "")
    if not target:
        target = "desconhecido"

    if ips is None:
        ips = [collected_data.get("ip", "")] if is_ip else \
              collected_data.get("dns", {}).get("A", [])

    logger.info(f"[enrichment] Iniciando enriquecimento para: {target} | IPs: {ips}")

    # result precisa existir antes de qualquer acesso a result["sources"]
    result: dict = {
        "target"      : target,
        "is_ip"       : is_ip,
        "enriched_at" : datetime.now().isoformat(),
        "sources"     : {},
    }

    # infra_agent é mais uma fonte — registra aqui para _build_summary ler
    result["sources"]["infra_agent"] = infra_data or {}

    # subdomínios e SSL — apenas domínios
    if not is_ip:
        for fetch_fn, key, fallback in [
            (lambda: fetch_subdomains(target), "subdomains", {"subdomains": [], "count": 0}),
            (lambda: fetch_ssl_info(target),   "ssl",        {}),
            (lambda: fetch_http_fingerprint(target), "http", {}),
        ]:
            try:
                result["sources"][key] = fetch_fn()
            except Exception as e:
                logger.warning(f"[enrichment] {key} falhou inesperadamente: {e}")
                result["sources"][key] = {**fallback, "error": str(e)}
    else:
        for key in ("subdomains", "ssl", "http"):
            result["sources"][key] = {"skipped": True, "reason": "Alvo é IP"}

    # VirusTotal — domínio ou IP
    try:
        result["sources"]["virustotal"] = fetch_virustotal(target)
    except Exception as e:
        logger.warning(f"[enrichment] virustotal falhou inesperadamente: {e}")
        result["sources"]["virustotal"] = {"error": str(e)}

    # por IP: Shodan full, AbuseIPDB, IPInfo
    shodan_results:    list[dict] = []
    abuseipdb_results: list[dict] = []
    ipinfo_results:    list[dict] = []

    for ip in ips:
        if not ip:
            continue
        shodan_results.append(fetch_shodan_full(ip))
        time.sleep(0.5)
        abuseipdb_results.append(fetch_abuseipdb(ip))
        ipinfo_results.append(fetch_ipinfo(ip))

    result["sources"]["shodan"]    = shodan_results    or [{"skipped": True}]
    result["sources"]["abuseipdb"] = abuseipdb_results or [{"skipped": True}]
    result["sources"]["ipinfo"]    = ipinfo_results    or [{"skipped": True}]

    result["summary"] = _build_summary(result)

    logger.info(
        f"[enrichment] Concluído para {target} — "
        f"subdomínios: {result['summary'].get('subdomain_count', 0)} | "
        f"CVEs: {result['summary'].get('total_cves', 0)} | "
        f"VT flagged: {result['summary'].get('vt_flagged', False)}"
    )

    return result


# ---------------------------------------------------------------------------
# Consolidação de dados para o ai_analyst
# ---------------------------------------------------------------------------

def _build_summary(result: dict) -> dict:
    """
    Consolida dados de todas as fontes em sumário para o ai_analyst.

    CVEs são truncados em _MAX_CVES_FOR_LLM para não estourar o contexto do LLM.
    O campo total_cves reflete o número real encontrado — só o que vai ao modelo
    é limitado.
    """
    summary: dict = {}

    # --- subdomínios ---
    subs = result["sources"].get("subdomains", {})
    summary["subdomain_count"] = subs.get("count", 0)
    summary["subdomains"]      = subs.get("subdomains", [])

    # --- CVEs: mescla infra_agent (InternetDB) + Shodan full API ---
    # infra_agent é a fonte primária — sempre disponível quando InternetDB rodou
    all_cves: list[str] = []

    infra = result["sources"].get("infra_agent", {})

    # infra_agent pode guardar CVEs em "vulns" (lista) ou "cves" (lista)
    infra_cves = infra.get("vulns") or infra.get("cves") or []
    if isinstance(infra_cves, list):
        all_cves.extend(infra_cves)

    # Shodan full API como fonte adicional (quando disponível)
    for shodan in result["sources"].get("shodan", []):
        if isinstance(shodan, dict):
            all_cves.extend(shodan.get("all_cves", []))

    unique_cves        = list(dict.fromkeys(all_cves))   # deduplica preservando ordem
    summary["total_cves"] = len(unique_cves)
    # trunca para não explodir o contexto do LLM — total_cves reflete o real
    summary["cves"]       = unique_cves[:_MAX_CVES_FOR_LLM]

    # --- portas: infra_agent tem a lista completa das 5 portas ---
    infra_ports = infra.get("open_ports") or []
    if not isinstance(infra_ports, list):
        infra_ports = []

    exposed_services = []

    # serviços com produto/versão vêm do Shodan full
    for shodan in result["sources"].get("shodan", []):
        if not isinstance(shodan, dict):
            continue
        for svc in shodan.get("services", []):
            if svc.get("product") or svc.get("version"):
                exposed_services.append({
                    "port"   : svc["port"],
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "cves"   : svc.get("cves", []),
                })

    # portas sem produto: completa com o que veio do InternetDB
    ports_with_product = {s["port"] for s in exposed_services}
    for port in infra_ports:
        if port not in ports_with_product:
            exposed_services.append({
                "port"   : port,
                "product": "",
                "version": "",
                "cves"   : [],
            })

    summary["exposed_services"] = exposed_services
    summary["all_open_ports"]   = infra_ports   # ai_analyst vê TODAS as portas

    # --- VirusTotal ---
    vt = result["sources"].get("virustotal", {})
    summary["vt_flagged"]      = vt.get("is_flagged", False)
    summary["vt_malicious"]    = vt.get("malicious", 0)
    summary["vt_threat_score"] = vt.get("threat_score", 0)

    # --- AbuseIPDB ---
    max_abuse = 0
    for ab in result["sources"].get("abuseipdb", []):
        if isinstance(ab, dict):
            max_abuse = max(max_abuse, ab.get("abuse_score", 0))
    summary["max_abuse_score"] = max_abuse
    summary["has_abusive_ip"]  = max_abuse >= 25

    # --- SSL ---
    ssl_info = result["sources"].get("ssl", {})
    summary["ssl_expiring_soon"] = ssl_info.get("expiring_soon", False)
    summary["ssl_expired"]       = ssl_info.get("expired", False)
    summary["ssl_wildcard"]      = ssl_info.get("is_wildcard", False)
    summary["ssl_sans"]          = ssl_info.get("sans", [])

    # --- HTTP fingerprint ---
    http = result["sources"].get("http", {})
    summary["missing_security_headers"] = http.get("missing_security_headers", [])
    summary["server_banner"]            = http.get("server", "")
    summary["tech_stack"]               = http.get("tech_stack", [])

    return summary