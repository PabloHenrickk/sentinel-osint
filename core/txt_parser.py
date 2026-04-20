"""
txt_parser.py — Extração de inteligência de registros DNS TXT

Registros TXT expõem serviços, integrações e provedores de forma passiva.
Petrobras.com.br: Salesforce, Dynatrace, AWS SES, IBM, Miro, Pexip — tudo no TXT.
Isso é mapa de superfície de ataque sem nenhuma interação ativa com o alvo.

Chamado em main.py após collector.run(), resultado vai ao ai_analyst como
txt_intelligence — contexto adicional de tecnologia para o LLM.
"""

from typing import Optional


# ── Mapa de fingerprints ──────────────────────────────────────────────────
# Padrão (substring, case-insensitive) → categoria → nome legível

FINGERPRINTS: dict[str, dict] = {

    # E-mail stack
    "include:amazonses.com":              {"category": "email_stack",    "name": "Amazon SES"},
    "include:sendgrid.net":               {"category": "email_stack",    "name": "SendGrid"},
    "include:mailgun.org":                {"category": "email_stack",    "name": "Mailgun"},
    "include:spf.protection.outlook.com": {"category": "email_stack",    "name": "Microsoft 365"},
    "include:_spf.google.com":            {"category": "email_stack",    "name": "Google Workspace"},
    "include:spf.mandrillapp.com":        {"category": "email_stack",    "name": "Mandrill (Mailchimp)"},
    "include:servers.mcsv.net":           {"category": "email_stack",    "name": "Mailchimp"},
    "include:spf.postmarkapp.com":        {"category": "email_stack",    "name": "Postmark"},

    # Segurança de e-mail (SPF/DMARC)
    "v=spf1":                             {"category": "email_security", "name": "SPF configurado"},
    "-all":                               {"category": "email_security", "name": "SPF política restritiva (-all)"},
    "~all":                               {"category": "email_security", "name": "SPF política suave (~all)"},
    "+all":                               {"category": "email_security", "name": "SPF permissivo (+all) — SPOOFING POSSÍVEL"},
    "v=dmarc1":                           {"category": "email_security", "name": "DMARC configurado"},
    "p=reject":                           {"category": "email_security", "name": "DMARC p=reject (máximo)"},
    "p=quarantine":                       {"category": "email_security", "name": "DMARC p=quarantine"},
    "p=none":                             {"category": "email_security", "name": "DMARC p=none (monitoramento apenas)"},

    # CRM / Marketing
    "salesforce":                         {"category": "crm",            "name": "Salesforce"},
    "pardot":                             {"category": "crm",            "name": "Salesforce Pardot"},
    "hubspot":                            {"category": "crm",            "name": "HubSpot"},
    "marketo":                            {"category": "crm",            "name": "Marketo"},
    "zendesk":                            {"category": "crm",            "name": "Zendesk"},

    # Monitoramento / APM
    "dynatrace":                          {"category": "monitoring",     "name": "Dynatrace"},
    "datadog":                            {"category": "monitoring",     "name": "Datadog"},
    "newrelic":                           {"category": "monitoring",     "name": "New Relic"},
    "splunk":                             {"category": "monitoring",     "name": "Splunk"},

    # Cloud
    "amazonaws":                          {"category": "cloud",          "name": "AWS"},
    "azure":                              {"category": "cloud",          "name": "Microsoft Azure"},
    "google-site-verification":           {"category": "cloud",          "name": "Google Cloud / GSuite"},
    "digitalocean":                       {"category": "cloud",          "name": "DigitalOcean"},
    "netlify":                            {"category": "cloud",          "name": "Netlify"},
    "vercel":                             {"category": "cloud",          "name": "Vercel"},

    # CDN
    "cloudflare":                         {"category": "cdn",            "name": "Cloudflare"},
    "fastly":                             {"category": "cdn",            "name": "Fastly"},
    "akamai":                             {"category": "cdn",            "name": "Akamai"},
    "incapsula":                          {"category": "cdn",            "name": "Imperva Incapsula"},

    # Colaboração
    "miro":                               {"category": "collaboration",  "name": "Miro"},
    "pexip":                              {"category": "collaboration",  "name": "Pexip"},
    "atlassian":                          {"category": "collaboration",  "name": "Atlassian (Jira/Confluence)"},
    "slack":                              {"category": "collaboration",  "name": "Slack"},
    "zoom.us":                            {"category": "collaboration",  "name": "Zoom"},
    "webex":                              {"category": "collaboration",  "name": "Cisco Webex"},

    # Identidade / SSO
    "okta":                               {"category": "identity",       "name": "Okta"},
    "onelogin":                           {"category": "identity",       "name": "OneLogin"},
    "duo":                                {"category": "identity",       "name": "Duo Security"},

    # Infraestrutura
    "ibm":                                {"category": "infrastructure", "name": "IBM"},
}


# ── Core ──────────────────────────────────────────────────────────────────

def parse(txt_records: list[str]) -> dict:
    """
    Parseia registros TXT e retorna inteligência estruturada de tecnologia.

    Args:
        txt_records: lista de strings dos registros TXT do DNS collector

    Returns:
        dict com serviços detectados, risco de e-mail e notas de superfície de ataque
    """
    if not txt_records:
        return _empty_result()

    detected: dict[str, list[str]] = {}
    raw_matches: list[dict]        = []

    for record in txt_records:
        record_lower = record.lower()
        for pattern, info in FINGERPRINTS.items():
            if pattern.lower() in record_lower:
                category = info["category"]
                name     = info["name"]
                if category not in detected:
                    detected[category] = []
                if name not in detected[category]:
                    detected[category].append(name)
                    raw_matches.append({
                        "pattern": pattern,
                        "name":    name,
                        "category": category,
                        "record_snippet": record[:120],
                    })

    return {
        "detected":              detected,
        "total_services":        sum(len(v) for v in detected.values()),
        "categories_found":      list(detected.keys()),
        "email_security_risk":   _evaluate_email_risk(detected.get("email_security", [])),
        "attack_surface_notes":  _generate_notes(detected),
        "raw_matches":           raw_matches,
    }


def _evaluate_email_risk(email_security: list[str]) -> str:
    """
    Classifica risco de spoofing baseado em SPF/DMARC presentes.
    Resultado vai diretamente como finding de severidade no ai_analyst.
    """
    has_spf         = any("SPF configurado" in s for s in email_security)
    has_dmarc       = any("DMARC configurado" in s for s in email_security)
    has_permissive  = any("+all" in s for s in email_security)
    has_reject      = any("reject" in s for s in email_security)

    if has_permissive:
        return "CRITICAL — SPF +all permite spoofing irrestrito do domínio"
    if not has_spf and not has_dmarc:
        return "HIGH — sem SPF nem DMARC, domínio vulnerável a e-mail spoofing"
    if has_spf and not has_dmarc:
        return "MEDIUM — SPF presente mas DMARC ausente"
    if has_spf and has_dmarc and has_reject:
        return "LOW — SPF + DMARC p=reject configurados corretamente"
    return "MEDIUM — configuração de e-mail parcial"


def _generate_notes(detected: dict[str, list[str]]) -> list[str]:
    """
    Gera notas de superfície de ataque baseadas nos serviços detectados.
    Contexto real de threat intelligence — não são vulnerabilidades, são vetores.
    """
    notes: list[str] = []

    if "crm" in detected:
        notes.append(
            f"CRM detectado ({', '.join(detected['crm'])}) — "
            "base de clientes é vetor de spear phishing direcionado"
        )
    if "monitoring" in detected:
        notes.append(
            f"Monitoramento ({', '.join(detected['monitoring'])}) — "
            "credenciais de APM são alvo de supply chain attacks"
        )
    if "cloud" in detected and len(detected["cloud"]) > 1:
        notes.append(
            f"Multi-cloud ({', '.join(detected['cloud'])}) — "
            "superfície distribuída, IAM misconfiguration é risco comum"
        )
    if "identity" in detected:
        notes.append(
            f"IdP/SSO ({', '.join(detected['identity'])}) — "
            "comprometer o IdP = acesso a todos os serviços integrados"
        )
    if "collaboration" in detected:
        notes.append(
            f"Colaboração ({', '.join(detected['collaboration'])}) — "
            "vetores de engenharia social e phishing interno via integração"
        )
    if "infrastructure" in detected:
        notes.append(
            f"Infraestrutura legada ({', '.join(detected['infrastructure'])}) — "
            "verificar exposição de serviços on-premise vs. cloud"
        )

    return notes


def _empty_result() -> dict:
    return {
        "detected":             {},
        "total_services":       0,
        "categories_found":     [],
        "email_security_risk":  "UNKNOWN — nenhum registro TXT disponível",
        "attack_surface_notes": [],
        "raw_matches":          [],
    }