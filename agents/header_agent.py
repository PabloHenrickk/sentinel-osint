"""
header_agent.py — Análise de Headers HTTP com findings para o ai_analyst

Verifica:
    - Headers de segurança ausentes (missing security headers)
    - Informações de versão/tecnologia vazadas (info leakage)
    - Configurações inseguras (CORS aberto, cookies sem flags)
    - Cookie security flags

Cada achado inclui severidade + mapeamento MITRE ATT&CK para
consumo direto pelo ai_analyst.
"""

import logging
from typing import Optional
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15
MAX_REDIRECTS = 5

# ---------------------------------------------------------------------------
# Definição dos headers de segurança esperados
# Formato: header_name → {severity, mitre_id, mitre_name, description, recommendation}
# ---------------------------------------------------------------------------
SECURITY_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "severity": "HIGH",
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "HSTS ausente — permite downgrade para HTTP e ataques MitM",
        "recommendation": "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "severity": "MEDIUM",
        "mitre_id": "T1059.007",
        "mitre_name": "Command and Scripting Interpreter: JavaScript",
        "description": "CSP ausente — sem proteção contra XSS e injeção de scripts",
        "recommendation": "Implementar CSP restritivo: Content-Security-Policy: default-src 'self'",
    },
    "x-frame-options": {
        "severity": "MEDIUM",
        "mitre_id": "T1185",
        "mitre_name": "Browser Session Hijacking",
        "description": "X-Frame-Options ausente — permite clickjacking via iframe",
        "recommendation": "Adicionar: X-Frame-Options: DENY ou SAMEORIGIN",
    },
    "x-content-type-options": {
        "severity": "LOW",
        "mitre_id": "T1059.007",
        "mitre_name": "Command and Scripting Interpreter: JavaScript",
        "description": "X-Content-Type-Options ausente — MIME-sniffing pode executar scripts inesperados",
        "recommendation": "Adicionar: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "LOW",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "Referrer-Policy ausente — URLs internas podem ser vazadas para terceiros",
        "recommendation": "Adicionar: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "LOW",
        "mitre_id": "T1592.004",
        "mitre_name": "Gather Victim Host Information: Client Configurations",
        "description": "Permissions-Policy ausente — sem controle sobre APIs do browser (câmera, microfone, geolocalização)",
        "recommendation": "Adicionar: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "cache-control": {
        "severity": "INFO",
        "mitre_id": "T1552",
        "mitre_name": "Unsecured Credentials",
        "description": "Cache-Control ausente — respostas sensíveis podem ser cacheadas por proxies intermediários",
        "recommendation": "Adicionar: Cache-Control: no-store, no-cache para endpoints autenticados",
    },
}

# ---------------------------------------------------------------------------
# Headers que revelam tecnologia/versão — info leakage
# ---------------------------------------------------------------------------
LEAKAGE_HEADERS: dict[str, dict] = {
    "server": {
        "severity": "LOW",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "Header Server vaza informações sobre software e versão do servidor",
    },
    "x-powered-by": {
        "severity": "LOW",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "Header X-Powered-By expõe linguagem/framework backend",
    },
    "x-aspnet-version": {
        "severity": "MEDIUM",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "Versão exata do ASP.NET exposta — facilita targeting de CVEs",
    },
    "x-aspnetmvc-version": {
        "severity": "MEDIUM",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "Versão do ASP.NET MVC exposta",
    },
    "x-generator": {
        "severity": "LOW",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "CMS ou gerador exposto via header X-Generator",
    },
    "x-drupal-cache": {
        "severity": "INFO",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "Header confirma uso de Drupal — alvo de CVEs específicos",
    },
    "x-wordpress-cache": {
        "severity": "INFO",
        "mitre_id": "T1592.002",
        "mitre_name": "Gather Victim Host Information: Software",
        "description": "Header confirma uso de WordPress — alvo frequente de exploits",
    },
}

# ---------------------------------------------------------------------------
# Verificações de CORS
# ---------------------------------------------------------------------------
def _check_cors(headers: dict) -> Optional[dict]:
    """Detecta CORS aberto (wildcard) como finding."""
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        return {
            "type": "cors_wildcard",
            "severity": "MEDIUM",
            "mitre_id": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "title": "CORS com wildcard (*) configurado",
            "description": "Access-Control-Allow-Origin: * permite que qualquer origem acesse recursos da API — risco em endpoints autenticados",
            "evidence": f"Access-Control-Allow-Origin: {acao}",
            "recommendation": "Restringir origens permitidas: Access-Control-Allow-Origin: https://seudominio.com",
        }
    return None


def _check_cookies(headers: dict) -> list[dict]:
    """
    Analisa cookies via Set-Cookie headers.
    Verifica flags Secure, HttpOnly, SameSite.
    """
    findings: list[dict] = []
    set_cookie = headers.get("set-cookie", "")

    if not set_cookie:
        return findings

    cookie_str = set_cookie.lower()

    if "secure" not in cookie_str:
        findings.append({
            "type": "cookie_no_secure",
            "severity": "MEDIUM",
            "mitre_id": "T1557",
            "mitre_name": "Adversary-in-the-Middle",
            "title": "Cookie sem flag Secure",
            "description": "Cookie pode ser transmitido via HTTP — interceptável em redes não criptografadas",
            "evidence": f"Set-Cookie: {set_cookie[:200]}",
            "recommendation": "Adicionar flag Secure em todos os cookies de sessão",
        })

    if "httponly" not in cookie_str:
        findings.append({
            "type": "cookie_no_httponly",
            "severity": "MEDIUM",
            "mitre_id": "T1059.007",
            "mitre_name": "Command and Scripting Interpreter: JavaScript",
            "title": "Cookie sem flag HttpOnly",
            "description": "Cookie acessível via JavaScript — vulnerável a roubo por XSS",
            "evidence": f"Set-Cookie: {set_cookie[:200]}",
            "recommendation": "Adicionar flag HttpOnly em todos os cookies de sessão",
        })

    if "samesite" not in cookie_str:
        findings.append({
            "type": "cookie_no_samesite",
            "severity": "LOW",
            "mitre_id": "T1185",
            "mitre_name": "Browser Session Hijacking",
            "title": "Cookie sem flag SameSite",
            "description": "Sem SameSite, cookie pode ser enviado em requisições cross-site — risco de CSRF",
            "evidence": f"Set-Cookie: {set_cookie[:200]}",
            "recommendation": "Adicionar SameSite=Strict ou SameSite=Lax nos cookies de sessão",
        })

    return findings


def run(target: str) -> dict:
    """
    Analisa headers HTTP de um alvo.

    Args:
        target: URL ou domínio (ex: 'https://example.com' ou 'example.com')

    Returns:
        Dict padronizado com findings para o pipeline do ai_analyst.
    """
    # Normaliza URL
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path

    logger.info("[header_agent] Analisando headers de %s", target)

    findings: list[dict] = []
    raw_headers: dict = {}
    final_url: str = target
    status_code: Optional[int] = None
    error: Optional[str] = None

    # --- Requisição HTTP ---
    try:
        resp = requests.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SentinelOSINT/1.0; +https://github.com/PabloHenrickk/sentinel-osint)"},
        )
        status_code = resp.status_code
        final_url = resp.url
        # Normaliza nomes de headers para lowercase
        raw_headers = {k.lower(): v for k, v in resp.headers.items()}
        logger.info("[header_agent] Resposta: %d — %d headers recebidos", status_code, len(raw_headers))

    except (requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout):
        # Qualquer falha em HTTPS → tenta HTTP como fallback
        # Cobre: SSLError, ConnectTimeout em 443, ConnectionError
        logger.warning("[header_agent] HTTPS falhou, tentando HTTP fallback")
        try:
            http_target = target.replace("https://", "http://")
            resp = requests.get(
                http_target,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SentinelOSINT/1.0)"},
            )
            status_code = resp.status_code
            final_url   = resp.url
            raw_headers = {k.lower(): v for k, v in resp.headers.items()}
            logger.info("[header_agent] HTTP fallback OK — %d", status_code)
            # HTTPS indisponível é finding HIGH independente do motivo
            findings.append({
                "type"          : "no_ssl",
                "severity"      : "HIGH",
                "mitre_id"      : "T1557",
                "mitre_name"    : "Adversary-in-the-Middle",
                "title"         : "HTTPS não disponível — apenas HTTP",
                "description"   : "Servidor não responde em HTTPS — todo tráfego é interceptável",
                "evidence"      : f"HTTPS falhou para {target}, HTTP respondeu em {http_target}",
                "recommendation": "Configurar certificado TLS válido e redirecionar HTTP → HTTPS",
            })
        except requests.exceptions.RequestException as exc:
            error = str(exc)
            logger.error("[header_agent] Falha total (HTTPS + HTTP): %s", exc)

    # Se não conseguiu conectar, retorna erro estruturado
    if error and not raw_headers:
        return {
            "domain": domain,
            "target_url": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status_code": None,
            "error": error,
            "findings": [],
            "raw_headers": {},
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }

    # --- Análise 1: Headers de segurança ausentes ---
    for header_name, meta in SECURITY_HEADERS.items():
        if header_name not in raw_headers:
            findings.append({
                "type": f"missing_{header_name.replace('-', '_')}",
                "severity": meta["severity"],
                "mitre_id": meta["mitre_id"],
                "mitre_name": meta["mitre_name"],
                "title": f"Header {header_name} ausente",
                "description": meta["description"],
                "evidence": f"Header '{header_name}' não presente na resposta",
                "recommendation": meta["recommendation"],
            })

    # --- Análise 2: Info leakage via headers ---
    for header_name, meta in LEAKAGE_HEADERS.items():
        if header_name in raw_headers:
            value = raw_headers[header_name]
            findings.append({
                "type": f"info_leak_{header_name.replace('-', '_')}",
                "severity": meta["severity"],
                "mitre_id": meta["mitre_id"],
                "mitre_name": meta["mitre_name"],
                "title": f"Informação vazada via {header_name}",
                "description": meta["description"],
                "evidence": f"{header_name}: {value}",
                "recommendation": f"Remover ou ocultar o header '{header_name}'",
            })

    # --- Análise 3: CORS ---
    cors_finding = _check_cors(raw_headers)
    if cors_finding:
        findings.append(cors_finding)

    # --- Análise 4: Cookies ---
    cookie_findings = _check_cookies(raw_headers)
    findings.extend(cookie_findings)

    # --- Sumário por severidade ---
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    result = {
        "domain": domain,
        "target_url": final_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status_code": status_code,
        "error": error,
        "findings": findings,
        "raw_headers": raw_headers,
        "summary": {
            "total_findings": len(findings),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "info": severity_counts["INFO"],
        },
    }

    logger.info(
        "[header_agent] Concluído: %d findings (%d HIGH, %d MEDIUM, %d LOW)",
        len(findings), severity_counts["HIGH"], severity_counts["MEDIUM"], severity_counts["LOW"]
    )

    return result


# ---------------------------------------------------------------------------
# Execução standalone para testes
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    result = run(target)

    print(f"\n{'='*60}")
    print(f"HEADER AGENT — {result['domain']}")
    print(f"{'='*60}")
    print(f"Status HTTP:  {result['status_code']}")
    print(f"Total findings: {result['summary']['total_findings']}")
    print(f"  HIGH:   {result['summary']['high']}")
    print(f"  MEDIUM: {result['summary']['medium']}")
    print(f"  LOW:    {result['summary']['low']}")
    print(f"  INFO:   {result['summary']['info']}")

    print(f"\nFINDINGS:")
    for f in result["findings"]:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(f["severity"], "⚪")
        print(f"  {icon} [{f['severity']}] {f['title']}")
        print(f"     MITRE: {f['mitre_id']} — {f['mitre_name']}")
        print(f"     {f.get('evidence', '')[:80]}")

    print(f"\n{'='*60}")
    print(json.dumps(result, indent=2, ensure_ascii=False))