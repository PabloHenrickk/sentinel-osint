"""
infra_agent.py — Reconhecimento de Infraestrutura com Fallback Multi-Provider

Substitui shodan_agent.py. Mantém a mesma interface: run(target) → dict
Pipeline: collector → validator → [infra_agent] → correlator → ai_analyst

Cadeia de providers (ordem de prioridade):
  1. Shodan InternetDB  — gratuito, sem key, sem limite documentado
  2. LeakIX             — 50 req/dia sem key, mais com LEAKIX_API_KEY
  3. ipinfo.io          — 50k req/mês sem key (geoloc + ASN)
  4. HackerTarget       — 100 req/dia sem key (portas básicas)
  5. Shodan API         — pago, usa SHODAN_API_KEY se disponível

Cada provider retorna o schema padrão ou levanta ProviderError.
O ProviderChain tenta na ordem e para no primeiro sucesso.
"""

import os
import re
import time
import requests
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import get_logger
from core.severity import classify_port, get_mitre

load_dotenv()
logger = get_logger(__name__)

# ── constantes ───────────────────────────────────────────────

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# timeout padrão para requests HTTP (segundos)
HTTP_TIMEOUT = int(os.getenv("INFRA_HTTP_TIMEOUT", "10"))

# CDNs conhecidas — se detectar, avisa mas não bloqueia a busca
CDN_RANGES = [
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
    "13.224.", "13.225.", "13.226.", "13.227.", "13.228.", "13.229.",
    "151.101.",
    "23.235.", "23.236.", "23.237.",  # Fastly adicional
    "104.64.", "104.65.", "104.66.",  # Akamai
    "23.32.",  "23.33.",  "23.34.",   # Akamai
    "34.96.",  "34.104.",             # Google Cloud CDN
    "104.199.",                       # Google Cloud CDN
]

CDN_MAP = {
    "104.1": "Cloudflare",
    "172.6": "Cloudflare",
    "13.22": "AWS CloudFront",
    "151."  : "Fastly",
    "23.23": "Fastly",
    "104.6": "Akamai",
    "23.32": "Akamai",
    "23.33": "Akamai",
    "23.34": "Akamai",
    "34.96": "Google Cloud CDN",
    "34.10": "Google Cloud CDN",
}


# ── exceção de provider ──────────────────────────────────────

class ProviderError(Exception):
    """Levantada quando um provider falha por qualquer motivo."""
    pass


# ── schema de saída padrão ───────────────────────────────────

def _empty_result(target: str) -> dict:
    """
    Schema base que todos os providers devem preencher.
    Campos não disponíveis ficam com valor padrão.
    """
    return {
        "target"       : target,
        "ip"           : target if IP_PATTERN.match(target) else None,
        "organization" : "desconhecido",
        "country"      : "desconhecido",
        "city"         : "desconhecido",
        "asn"          : None,
        "os"           : None,
        "hostnames"    : [],
        "open_ports"   : [],
        "services"     : [],
        "vulns"        : [],
        "tags"         : [],
        "total_ports"  : 0,
        "cdn_detected" : None,
        "provider_used": None,
        "collected_at" : datetime.now().isoformat(),
    }


# ── helpers ──────────────────────────────────────────────────

def detect_cdn(ip: str) -> Optional[str]:
    """Retorna nome da CDN se o IP pertencer a um range conhecido."""
    for prefix in CDN_RANGES:
        if ip.startswith(prefix):
            for key, name in CDN_MAP.items():
                if ip.startswith(key):
                    return name
            return "CDN desconhecida"
    return None


def _get_attack_type(port: int) -> str:
    """Mapeia porta para categoria de ataque para lookup no MITRE."""
    mapping = {
        frozenset({1433, 3306, 5432, 9200, 27017, 6379, 5984}): "database_exposed",
        frozenset({3389})                                       : "rdp_exposed",
        frozenset({22})                                         : "ssh_exposed",
        frozenset({21})                                         : "ftp_exposed",
        frozenset({445, 139})                                   : "smb_exposed",
        frozenset({23})                                         : "telnet_exposed",
    }
    for ports, attack_type in mapping.items():
        if port in ports:
            return attack_type
    return ""


def _build_service(port: int, protocol: str = "tcp",
                   service_name: str = "desconhecido",
                   version: str = "", banner: str = "") -> dict:
    """
    Monta objeto de serviço com classificação de severidade e MITRE.
    Centraliza a lógica para todos os providers.
    """
    classification = classify_port(port)
    attack_type    = _get_attack_type(port)
    mitre          = get_mitre(attack_type) if attack_type else {}

    return {
        "port"       : port,
        "protocol"   : protocol,
        "service"    : service_name,
        "version"    : version,
        "banner"     : banner[:800],
        "severity"   : classification["severity"],
        "description": classification["description"],
        "mitre"      : mitre,
    }


def _safe_get(url: str, params: Optional[dict] = None,
              headers: Optional[dict] = None) -> requests.Response:
    """
    GET com timeout e tratamento de erro de rede centralizado.
    Levanta ProviderError em qualquer falha de conectividade.
    """
    try:
        response = requests.get(
            url,
            params=params,
            headers=headers or {},
            timeout=HTTP_TIMEOUT,
        )
        return response
    except requests.exceptions.Timeout:
        raise ProviderError(f"Timeout ({HTTP_TIMEOUT}s) em {url}")
    except requests.exceptions.ConnectionError as e:
        raise ProviderError(f"Erro de conexão em {url}: {e}")
    except requests.exceptions.RequestException as e:
        raise ProviderError(f"Erro HTTP em {url}: {e}")


# ── provider 1: Shodan InternetDB ────────────────────────────

def provider_internetdb(ip: str) -> dict:
    """
    Shodan InternetDB — API pública gratuita, sem key, sem limite documentado.
    Retorna: portas, CVEs, hostnames, tags, CPEs.
    Endpoint: https://internetdb.shodan.io/{ip}
    """
    logger.info(f"[infra_agent] InternetDB → {ip}")

    response = _safe_get(f"https://internetdb.shodan.io/{ip}")

    if response.status_code == 404:
        raise ProviderError(f"InternetDB: IP {ip} não indexado")

    if response.status_code != 200:
        raise ProviderError(f"InternetDB retornou {response.status_code}")

    data   = response.json()
    result = _empty_result(ip)

    ports    = data.get("ports", [])
    services = [_build_service(p) for p in ports]

    result.update({
        "ip"           : ip,
        "hostnames"    : data.get("hostnames", []),
        "open_ports"   : ports,
        "services"     : services,
        "vulns"        : data.get("vulns", []),
        "tags"         : data.get("tags", []),
        "total_ports"  : len(ports),
        "provider_used": "shodan_internetdb",
    })

    logger.info(f"[infra_agent] InternetDB: {len(ports)} porta(s) em {ip}")
    return result


# ── provider 2: LeakIX ───────────────────────────────────────

def provider_leakix(ip: str) -> dict:
    """
    LeakIX — 50 req/dia sem key, mais com LEAKIX_API_KEY no .env.
    Retorna: serviços expostos, leaks, software.
    """
    logger.info(f"[infra_agent] LeakIX → {ip}")

    api_key = os.getenv("LEAKIX_API_KEY", "")
    headers = {"api-key": api_key} if api_key else {}

    response = _safe_get(
        f"https://leakix.net/host/{ip}",
        headers={**headers, "Accept": "application/json"},
    )

    if response.status_code == 429:
        raise ProviderError("LeakIX: rate limit atingido")

    if response.status_code == 404:
        raise ProviderError(f"LeakIX: IP {ip} não indexado")

    if response.status_code != 200:
        raise ProviderError(f"LeakIX retornou {response.status_code}")

    data   = response.json()
    result = _empty_result(ip)

    # LeakIX retorna lista de eventos (serviços encontrados)
    events = data if isinstance(data, list) else data.get("Services", [])

    ports    = []
    services = []

    for event in events:
        port = event.get("port")
        if port and isinstance(port, (int, str)):
            port = int(port)
            ports.append(port)
            svc = _build_service(
                port         = port,
                service_name = event.get("protocol", "desconhecido"),
                banner       = event.get("summary", ""),
            )
            services.append(svc)

    result.update({
        "ip"           : ip,
        "open_ports"   : ports,
        "services"     : services,
        "total_ports"  : len(ports),
        "provider_used": "leakix",
    })

    logger.info(f"[infra_agent] LeakIX: {len(ports)} porta(s) em {ip}")
    return result


# ── provider 3: ipinfo.io ────────────────────────────────────

def provider_ipinfo(ip: str) -> dict:
    """
    ipinfo.io — 50k req/mês sem key, mais com IPINFO_TOKEN no .env.
    Retorna: geoloc, ASN, organização. Não retorna portas.
    Usado como enriquecimento quando outros providers falham.
    """
    logger.info(f"[infra_agent] ipinfo → {ip}")

    token   = os.getenv("IPINFO_TOKEN", "")
    params  = {"token": token} if token else {}
    response = _safe_get(f"https://ipinfo.io/{ip}/json", params=params)

    if response.status_code == 429:
        raise ProviderError("ipinfo: rate limit atingido")

    if response.status_code != 200:
        raise ProviderError(f"ipinfo retornou {response.status_code}")

    data   = response.json()
    result = _empty_result(ip)

    # ASN vem como "AS15169 Google LLC" — separa número e nome
    org = data.get("org", "")
    asn = org.split(" ")[0] if org else None

    loc      = data.get("loc", "").split(",")
    city     = data.get("city", "desconhecido")
    country  = data.get("country", "desconhecido")
    hostname = data.get("hostname", "")

    result.update({
        "ip"           : ip,
        "organization" : org,
        "country"      : country,
        "city"         : city,
        "asn"          : asn,
        "hostnames"    : [hostname] if hostname else [],
        "provider_used": "ipinfo",
        # ipinfo não tem portas — retorna enriquecimento de contexto apenas
        "_note"        : "ipinfo: sem dados de porta — apenas geoloc e ASN",
    })

    logger.info(f"[infra_agent] ipinfo: org={org} country={country}")
    return result


# ── provider 4: HackerTarget ─────────────────────────────────

def provider_hackertarget(ip: str) -> dict:
    """
    HackerTarget — 100 req/dia sem key.
    Retorna: portas abertas básicas via nmap online.
    """
    logger.info(f"[infra_agent] HackerTarget → {ip}")

    response = _safe_get(
        "https://api.hackertarget.com/nmap/",
        params={"q": ip},
    )

    if response.status_code == 429:
        raise ProviderError("HackerTarget: rate limit atingido")

    if response.status_code != 200:
        raise ProviderError(f"HackerTarget retornou {response.status_code}")

    text = response.text.strip()

    # erros retornam como texto plano
    if "error" in text.lower() or "API count" in text:
        raise ProviderError(f"HackerTarget: {text[:100]}")

    # parse do output nmap: "22/tcp  open  ssh"
    ports    = []
    services = []

    for line in text.splitlines():
        parts = line.split()
        # formato esperado: "PORT/PROTO  STATE  SERVICE"
        if len(parts) >= 3 and "/" in parts[0] and parts[1] == "open":
            try:
                port_str, proto = parts[0].split("/")
                port     = int(port_str)
                svc_name = parts[2] if len(parts) > 2 else "desconhecido"

                ports.append(port)
                services.append(_build_service(
                    port         = port,
                    protocol     = proto,
                    service_name = svc_name,
                ))
            except (ValueError, IndexError):
                continue

    if not ports:
        raise ProviderError("HackerTarget: nenhuma porta encontrada no output")

    result = _empty_result(ip)
    result.update({
        "ip"           : ip,
        "open_ports"   : ports,
        "services"     : services,
        "total_ports"  : len(ports),
        "provider_used": "hackertarget",
    })

    logger.info(f"[infra_agent] HackerTarget: {len(ports)} porta(s) em {ip}")
    return result


# ── provider 5: Shodan API (pago, fallback final) ────────────

def provider_shodan_api(ip: str) -> dict:
    """
    Shodan API clássica — usa SHODAN_API_KEY do .env.
    Fallback final quando todos os gratuitos falham.
    Só tenta se a key existir no .env.
    """
    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    if not api_key:
        raise ProviderError("Shodan API: SHODAN_API_KEY não configurada no .env")

    logger.info(f"[infra_agent] Shodan API → {ip}")

    try:
        import shodan as shodan_lib
        from core.retry import with_retry
    except ImportError:
        raise ProviderError("Shodan API: pacote 'shodan' não instalado")

    try:
        client = shodan_lib.Shodan(api_key)
        host   = with_retry(lambda: client.host(ip))
    except shodan_lib.APIError as e:
        raise ProviderError(f"Shodan API: {e}")

    services = []
    for item in host.get("data", []):
        port = item.get("port")
        if port:
            svc = _build_service(
                port         = port,
                protocol     = item.get("transport", "tcp"),
                service_name = item.get("product", "desconhecido"),
                version      = item.get("version", ""),
                banner       = item.get("data", ""),
            )
            services.append(svc)

    result = _empty_result(ip)
    result.update({
        "ip"           : ip,
        "organization" : host.get("org", "desconhecido"),
        "country"      : host.get("country_name", "desconhecido"),
        "city"         : host.get("city", "desconhecido"),
        "os"           : host.get("os"),
        "hostnames"    : host.get("hostnames", []),
        "open_ports"   : [s["port"] for s in services],
        "services"     : services,
        "vulns"        : list(host.get("vulns", {}).keys()),
        "total_ports"  : len(services),
        "provider_used": "shodan_api",
    })

    logger.info(f"[infra_agent] Shodan API: {len(services)} serviço(s) em {ip}")
    return result


# ── gerenciador de providers ─────────────────────────────────

# cadeia de providers em ordem de prioridade
# cada item: (nome, função, requer_ip)
# requer_ip=True → provider só aceita IP, não domínio
PROVIDER_CHAIN = [
    ("shodan_internetdb", provider_internetdb, True),
    ("leakix",            provider_leakix,     True),
    ("hackertarget",      provider_hackertarget, True),
    ("ipinfo",            provider_ipinfo,     True),
    ("shodan_api",        provider_shodan_api, True),
]


def resolve_ip_from_domain(domain: str) -> Optional[str]:
    """
    Resolve IP de domínio usando dnspython (já dependência do projeto).
    Retorna primeiro IP encontrado ou None.
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "A")
        ip = str(answers[0])
        logger.info(f"[infra_agent] {domain} → {ip}")
        return ip
    except Exception as e:
        logger.warning(f"[infra_agent] Falha ao resolver {domain}: {e}")
        return None


def run_provider_chain(ip: str) -> dict:
    """
    Tenta cada provider na ordem. Para no primeiro sucesso.
    Se todos falharem, retorna resultado vazio com log de todas as falhas.
    """
    failures: list[str] = []

    for name, provider_fn, _ in PROVIDER_CHAIN:
        try:
            result = provider_fn(ip)
            logger.info(f"[infra_agent] Sucesso via {name}")
            return result

        except ProviderError as e:
            logger.warning(f"[infra_agent] {name} falhou: {e}")
            failures.append(f"{name}: {e}")

        except Exception as e:
            # erro inesperado — loga e continua
            logger.error(f"[infra_agent] {name} erro inesperado: {e}")
            failures.append(f"{name}: erro inesperado — {e}")

    # todos falharam
    logger.error(f"[infra_agent] Todos os providers falharam para {ip}")
    result = _empty_result(ip)
    result["error"]           = "Todos os providers falharam"
    result["provider_errors"] = failures
    return result


# ── função principal (interface pública) ─────────────────────

def run(target: str) -> dict:
    """
    Ponto de entrada público. Mantém interface idêntica ao shodan_agent.
    Detecta automaticamente IP vs domínio.

    Parâmetros:
        target → IP (ex: "8.8.8.8") ou domínio (ex: "example.com")

    Retorna:
        dict com schema padrão — nunca levanta exceção.
    """
    logger.info(f"[infra_agent] Iniciando para: {target}")

    # resolve domínio para IP se necessário
    if IP_PATTERN.match(target):
        ip     = target
        domain = None
    else:
        domain = target
        ip     = resolve_ip_from_domain(target)
        if not ip:
            result         = _empty_result(target)
            result["error"] = f"Não foi possível resolver IP para {target}"
            return result

    # detecta CDN antes de buscar
    cdn = detect_cdn(ip)
    if cdn:
        logger.warning(
            f"[infra_agent] {ip} pertence a {cdn} — "
            f"dados refletem a CDN, não o servidor de origem"
        )

    # executa a cadeia de providers
    result = run_provider_chain(ip)

    # enriquece com contexto de domínio e CDN
    if domain:
        result["domain"] = domain
    if cdn:
        result["cdn_detected"] = cdn

    return result
