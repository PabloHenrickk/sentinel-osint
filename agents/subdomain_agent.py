"""
subdomain_agent.py — Enumeração de subdomínios com detecção de takeover

Fontes:
    - crt.sh (Certificate Transparency Logs) via API JSON
    - dnspython para resolução A + CNAME por subdomínio

Output padronizado para o pipeline do ai_analyst.
"""

import json
import time
import logging
from typing import Optional
from datetime import datetime, timezone

import requests
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Serviços de nuvem conhecidos — CNAME apontando para estes sem IP válido
# indica risco de subdomain takeover
# ---------------------------------------------------------------------------
TAKEOVER_FINGERPRINTS: dict[str, str] = {
    "github.io":          "GitHub Pages não reivindicado",
    "herokuapp.com":      "Heroku app não provisionado",
    "s3.amazonaws.com":   "Bucket S3 público não reivindicado",
    "s3-website":         "Bucket S3 Website não reivindicado",
    "cloudfront.net":     "CloudFront distribution inativa",
    "azurewebsites.net":  "Azure Web App não provisionado",
    "azureedge.net":      "Azure CDN não provisionado",
    "netlify.app":        "Netlify site não publicado",
    "vercel.app":         "Vercel deployment não ativo",
    "myshopify.com":      "Shopify store não reivindicado",
    "shopify.com":        "Shopify store não reivindicado",
    "fastly.net":         "Fastly origin não configurado",
    "ghost.io":           "Ghost.io blog não reivindicado",
    "helpscoutdocs.com":  "HelpScout docs não reivindicado",
    "zendesk.com":        "Zendesk subdomain não reivindicado",
    "freshdesk.com":      "Freshdesk portal não reivindicado",
    "surge.sh":           "Surge.sh site não publicado",
    "launchrock.com":     "Launchrock page não reivindicada",
    "bitbucket.io":       "Bitbucket Pages não reivindicado",
    "readthedocs.io":     "ReadTheDocs project não reivindicado",
    "statuspage.io":      "Atlassian Statuspage não reivindicada",
    "webflow.io":         "Webflow site não publicado",
    "hubspotpagebuilder": "HubSpot page não reivindicada",
    "pantheonsite.io":    "Pantheon site não provisionado",
    "wpengine.com":       "WP Engine não provisionado",
    "kinsta.com":         "Kinsta site não provisionado",
}

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRT_SH_TIMEOUT = 30  # crt.sh pode ser lento
DNS_TIMEOUT = 5


def _query_crt_sh(domain: str) -> list[str]:
    """
    Consulta Certificate Transparency Logs via crt.sh.
    Retorna lista de subdomínios únicos, sem wildcards.
    """
    url = CRT_SH_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=CRT_SH_TIMEOUT)
        resp.raise_for_status()
        entries = resp.json()
    except requests.exceptions.Timeout:
        logger.warning("crt.sh timeout para %s", domain)
        return []
    except requests.exceptions.HTTPError as exc:
        logger.warning("crt.sh HTTP error %s: %s", domain, exc)
        return []
    except (requests.exceptions.RequestException, ValueError) as exc:
        logger.error("crt.sh falhou para %s: %s", domain, exc)
        return []

    subdomains: set[str] = set()
    for entry in entries:
        # Cada entrada pode conter múltiplos nomes separados por \n
        names_raw: str = entry.get("name_value", "")
        for name in names_raw.splitlines():
            name = name.strip().lower()
            # Remove wildcards e entradas vazias
            if name.startswith("*."):
                name = name[2:]
            if name and name.endswith(f".{domain}"):
                subdomains.add(name)
            elif name == domain:
                pass  # domínio raiz — ignora

    return sorted(subdomains)


def _resolve_subdomain(subdomain: str) -> dict:
    """
    Resolve um subdomínio via DNS.
    Retorna IPs (A records), CNAME chain e status.
    """
    result = {
        "name": subdomain,
        "ips": [],
        "cname": None,
        "status": "unknown",
        "takeover_risk": False,
        "takeover_service": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT

    # --- Tenta A record direto ---
    try:
        answers = resolver.resolve(subdomain, "A")
        result["ips"] = [str(r) for r in answers]
        result["status"] = "resolved"
    except dns.resolver.NXDOMAIN:
        result["status"] = "nxdomain"
    except dns.resolver.NoAnswer:
        result["status"] = "no_answer"
    except dns.exception.Timeout:
        result["status"] = "timeout"
    except dns.resolver.NoNameservers:
        result["status"] = "no_nameservers"
    except Exception as exc:
        logger.debug("Erro resolvendo A %s: %s", subdomain, exc)
        result["status"] = "error"

    # --- Tenta CNAME para detectar chains e takeover ---
    try:
        cname_answers = resolver.resolve(subdomain, "CNAME")
        cname_target = str(cname_answers[0].target).rstrip(".")
        result["cname"] = cname_target

        # Verifica takeover: CNAME aponta para serviço conhecido + sem IP
        for fingerprint, description in TAKEOVER_FINGERPRINTS.items():
            if fingerprint in cname_target:
                # Risco confirmado se sem IPs OU NXDOMAIN no destino
                if not result["ips"] or result["status"] in ("nxdomain", "no_answer"):
                    result["takeover_risk"] = True
                    result["takeover_service"] = description
                break

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass  # Sem CNAME — não é erro
    except Exception as exc:
        logger.debug("Erro resolvendo CNAME %s: %s", subdomain, exc)

    return result


def run(domain: str, max_subdomains: int = 200, delay: float = 0.15) -> dict:
    """
    Executa enumeração completa de subdomínios.

    Args:
        domain:         Domínio raiz (ex: 'example.com')
        max_subdomains: Limite de subdomínios a resolver (proteção contra floods)
        delay:          Delay em segundos entre resoluções DNS (evita rate limit)

    Returns:
        Dict padronizado para o pipeline do ai_analyst.
    """
    logger.info("[subdomain_agent] Iniciando para %s", domain)

    # --- Fase 1: Enumeração via crt.sh ---
    subdomains_found = _query_crt_sh(domain)
    total_found = len(subdomains_found)
    logger.info("[subdomain_agent] crt.sh retornou %d subdomínios únicos", total_found)

    # Limita para não travar o pipeline em domínios com centenas de subdomínios
    subdomains_to_resolve = subdomains_found[:max_subdomains]
    truncated = total_found > max_subdomains

    # --- Fase 2: Resolução DNS de cada subdomínio ---
    resolved: list[dict] = []
    takeover_candidates: list[dict] = []

    for sub in subdomains_to_resolve:
        data = _resolve_subdomain(sub)
        resolved.append(data)

        if data["takeover_risk"]:
            takeover_candidates.append(data)
            logger.warning(
                "[subdomain_agent] TAKEOVER RISK: %s → %s (%s)",
                sub, data["cname"], data["takeover_service"]
            )

        time.sleep(delay)

    # --- Sumário ---
    active = [r for r in resolved if r["status"] == "resolved"]
    dead   = [r for r in resolved if r["status"] == "nxdomain"]

    summary = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "crt.sh + dnspython",
        "total_found_crt": total_found,
        "total_resolved": len(subdomains_to_resolve),
        "truncated": truncated,
        "active_count": len(active),
        "dead_count": len(dead),
        "takeover_candidates_count": len(takeover_candidates),
        "subdomains": resolved,
        "takeover_candidates": takeover_candidates,
    }

    logger.info(
        "[subdomain_agent] Concluído: %d ativos, %d mortos, %d riscos de takeover",
        len(active), len(dead), len(takeover_candidates)
    )

    return summary


# ---------------------------------------------------------------------------
# Execução standalone para testes
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    result = run(target)

    print(f"\n{'='*60}")
    print(f"SUBDOMAIN AGENT — {result['domain']}")
    print(f"{'='*60}")
    print(f"Total no crt.sh:    {result['total_found_crt']}")
    print(f"Ativos:             {result['active_count']}")
    print(f"NXDOMAIN:           {result['dead_count']}")
    print(f"Risco de takeover:  {result['takeover_candidates_count']}")

    if result["takeover_candidates"]:
        print("\n⚠️  TAKEOVER CANDIDATES:")
        for tc in result["takeover_candidates"]:
            print(f"  {tc['name']} → {tc['cname']} ({tc['takeover_service']})")

    print(f"\n{'='*60}")
    print(json.dumps(result, indent=2, ensure_ascii=False))
