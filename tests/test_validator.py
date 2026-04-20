"""
tests/test_validator.py — Cobertura completa do validator.py

Cobre:
  - validate_domain_format: regex, edge cases de IP e string vazia
  - validate_whois: campos obrigatórios, chave 'error', extras ignorados
  - validate_dns_domain: presença de A records
  - validate_dns_ip: combinações de A e PTR, edge case PTR-sem-A
  - calculate_confidence: domínio vs IP, scores parciais
  - run(): lógica de aprovação, warnings, target_type, skip de checks para IPs

Princípio central: approved = integrity_ok (DNS resolveu), NUNCA = score >= threshold.
Score baixo gera warning, nunca bloqueio.

Execute:
    pytest tests/test_validator.py -v
"""

import pytest

from agents.validator import (
    APPROVAL_THRESHOLD,
    calculate_confidence,
    run,
    validate_dns_domain,
    validate_dns_ip,
    validate_domain_format,
    validate_whois,
)


# ---------------------------------------------------------------------------
# validate_domain_format
# ---------------------------------------------------------------------------

class TestValidateDomainFormat:
    """Valida regex de domínio — 20pts se válido, 0 se inválido."""

    def test_dotcom_valido(self):
        r = validate_domain_format("example.com")
        assert r["valid"] is True
        assert r["score"] == 20
        assert r["reason"] is None

    def test_dotcombr_valido(self):
        r = validate_domain_format("example.com.br")
        assert r["valid"] is True
        assert r["score"] == 20

    def test_subdominio_valido(self):
        r = validate_domain_format("mail.sub.example.org")
        assert r["valid"] is True
        assert r["score"] == 20

    def test_sem_tld_invalido(self):
        r = validate_domain_format("localhost")
        assert r["valid"] is False
        assert r["score"] == 0
        assert r["reason"] is not None

    def test_ip_nao_aprovado_pelo_regex(self):
        # IP não passa: TLD deve ter só letras ([a-zA-Z]{2,}) — dígito reprovado
        r = validate_domain_format("192.168.1.1")
        assert r["valid"] is False
        assert r["score"] == 0

    def test_string_vazia_invalida(self):
        r = validate_domain_format("")
        assert r["valid"] is False
        assert r["score"] == 0

    def test_dominio_com_hifen_valido(self):
        r = validate_domain_format("my-site.example.com")
        assert r["valid"] is True
        assert r["score"] == 20


# ---------------------------------------------------------------------------
# validate_whois
# ---------------------------------------------------------------------------

class TestValidateWhois:
    """40pts se registrar + creation_date presentes, 0 se qualquer erro."""

    def test_whois_completo(self):
        r = validate_whois({"registrar": "GoDaddy", "creation_date": "2010-01-01"})
        assert r["valid"] is True
        assert r["score"] == 40
        assert r["reason"] is None

    def test_whois_com_chave_error(self):
        # 'error' no dict → timeout ou bloqueio do registrar
        r = validate_whois({"error": "lookup timeout"})
        assert r["valid"] is False
        assert r["score"] == 0

    def test_whois_sem_registrar(self):
        r = validate_whois({"creation_date": "2010-01-01"})
        assert r["valid"] is False
        assert r["score"] == 0
        assert "registrar" in r["reason"]

    def test_whois_sem_creation_date(self):
        r = validate_whois({"registrar": "GoDaddy"})
        assert r["valid"] is False
        assert r["score"] == 0
        assert "creation_date" in r["reason"]

    def test_whois_com_campos_extras(self):
        # Campos adicionais não devem interferir na pontuação
        r = validate_whois({
            "registrar": "NameCheap",
            "creation_date": "2015-06-01",
            "expiry_date": "2030-06-01",
            "name_servers": ["ns1.example.com"],
        })
        assert r["valid"] is True
        assert r["score"] == 40

    def test_whois_campos_com_valores_falsy(self):
        # None e "" são falsy — campos "ausentes" mesmo presentes
        r = validate_whois({"registrar": None, "creation_date": ""})
        assert r["valid"] is False
        assert r["score"] == 0


# ---------------------------------------------------------------------------
# validate_dns_domain
# ---------------------------------------------------------------------------

class TestValidateDnsDomain:
    """Para domínios: 40pts se tem A records, 0 se não tem."""

    def test_com_a_records(self):
        r = validate_dns_domain({"A": ["1.2.3.4"]})
        assert r["valid"] is True
        assert r["score"] == 40

    def test_multiplos_a_records(self):
        r = validate_dns_domain({"A": ["1.2.3.4", "5.6.7.8"]})
        assert r["valid"] is True
        assert r["score"] == 40

    def test_lista_a_vazia(self):
        r = validate_dns_domain({"A": []})
        assert r["valid"] is False
        assert r["score"] == 0

    def test_sem_chave_a(self):
        # .get("A", []) → lista vazia
        r = validate_dns_domain({})
        assert r["valid"] is False
        assert r["score"] == 0

    def test_so_mx_sem_a(self):
        # DNS com MX mas sem A — domínio pode receber e-mail mas não resolve
        r = validate_dns_domain({"MX": ["mail.example.com"]})
        assert r["valid"] is False
        assert r["score"] == 0


# ---------------------------------------------------------------------------
# validate_dns_ip
# ---------------------------------------------------------------------------

class TestValidateDnsIp:
    """
    Para IPs: PTR(60pts) + A(40pts) = max 100.
    Edge case crítico: PTR sem A → score 60 → valid=True (60 >= 40).
    Score mínimo para valid=True é 40 (IP confirmado, sem PTR).
    """

    def test_a_e_ptr_presentes(self):
        r = validate_dns_ip({"A": ["1.2.3.4"], "PTR": ["host.example.com"]})
        assert r["valid"] is True
        assert r["score"] == 100
        assert r["reason"] is None

    def test_a_presente_ptr_ausente(self):
        # Comum em CDNs — válido, mas avisa sobre PTR
        r = validate_dns_ip({"A": ["1.2.3.4"], "PTR": []})
        assert r["valid"] is True   # 40 >= 40 → aprovado
        assert r["score"] == 40
        assert r["reason"] is not None  # warning de PTR ausente

    def test_ptr_sem_a_edge_case(self):
        # Edge case: sem A mas PTR existe → score=60 → valid=True (60 >= 40)
        # Incomum mas possível — o agente não bloqueia
        r = validate_dns_ip({"A": [], "PTR": ["host.example.com"]})
        assert r["score"] == 60
        assert r["valid"] is True

    def test_sem_a_sem_ptr(self):
        r = validate_dns_ip({"A": [], "PTR": []})
        assert r["valid"] is False
        assert r["score"] == 0

    def test_ptr_records_incluidos_no_resultado(self):
        ptr = ["ns1.google.com"]
        r = validate_dns_ip({"A": ["8.8.8.8"], "PTR": ptr})
        assert r["ptr_records"] == ptr


# ---------------------------------------------------------------------------
# calculate_confidence
# ---------------------------------------------------------------------------

class TestCalculateConfidence:
    """Domínio soma os 3 checks. IP usa só dns['score']."""

    def _checks(self, fmt=0, whois=0, dns=0):
        return {
            "domain_format": {"score": fmt},
            "whois": {"score": whois},
            "dns": {"score": dns},
        }

    def test_dominio_score_maximo(self):
        assert calculate_confidence(self._checks(20, 40, 40), is_ip=False) == 100

    def test_dominio_whois_zero(self):
        # WHOIS falhou — score parcial
        assert calculate_confidence(self._checks(20, 0, 40), is_ip=False) == 60

    def test_dominio_score_zero(self):
        assert calculate_confidence(self._checks(0, 0, 0), is_ip=False) == 0

    def test_ip_ignora_format_e_whois(self):
        # Mesmo que format e whois tenham score, IP usa só dns
        checks = self._checks(fmt=20, whois=40, dns=40)
        assert calculate_confidence(checks, is_ip=True) == 40

    def test_ip_score_maximo(self):
        checks = self._checks(dns=100)
        assert calculate_confidence(checks, is_ip=True) == 100


# ---------------------------------------------------------------------------
# run() — integração
# ---------------------------------------------------------------------------

class TestRun:
    """
    Testa o fluxo completo do validator.
    Princípio: approved = integrity_ok, score baixo NÃO bloqueia.
    """

    # --- Fixtures ---

    def _dominio(self, **overrides) -> dict:
        base = {
            "is_ip": False,
            "domain": "example.com",
            "whois": {"registrar": "GoDaddy", "creation_date": "2010-01-01"},
            "dns": {"A": ["1.2.3.4"]},
        }
        base.update(overrides)
        return base

    def _ip(self, **overrides) -> dict:
        base = {
            "is_ip": True,
            "ip": "8.8.8.8",
            "whois": {},
            "dns": {"A": ["8.8.8.8"], "PTR": ["dns.google"]},
        }
        base.update(overrides)
        return base

    # --- Domínio --- happy path

    def test_dominio_completo_aprovado(self):
        r = run(self._dominio())
        assert r["approved"] is True
        assert r["confidence_score"] == 100
        assert r["target_type"] == "domain"
        assert r["warnings"] == []

    def test_dominio_sem_dns_reprovado(self):
        r = run(self._dominio(dns={"A": []}))
        assert r["approved"] is False
        assert r["integrity_ok"] is False

    # --- Score baixo NÃO bloqueia ---

    def test_dominio_whois_com_error_aprovado_com_warning(self):
        # WHOIS retornou erro → score cai, mas DNS ok → aprovado
        r = run(self._dominio(whois={"error": "timeout"}))
        assert r["approved"] is True
        assert r["confidence_score"] < APPROVAL_THRESHOLD
        # Warning deve mencionar o score baixo
        score_str = str(r["confidence_score"])
        assert any(score_str in w for w in r["warnings"])

    def test_dominio_whois_parcial_warning_de_whois(self):
        # Falta creation_date → WHOIS inválido → warning específico de WHOIS
        r = run(self._dominio(whois={"registrar": "GoDaddy"}))
        assert r["approved"] is True
        assert any("WHOIS" in w for w in r["warnings"])

    # --- IP --- happy path

    def test_ip_completo_aprovado(self):
        r = run(self._ip())
        assert r["approved"] is True
        assert r["confidence_score"] == 100
        assert r["target_type"] == "ip"

    def test_ip_sem_ptr_aprovado(self):
        # Sem PTR → score=40, mas aprovado (CDN/cloud é normal)
        r = run(self._ip(dns={"A": ["8.8.8.8"], "PTR": []}))
        assert r["approved"] is True
        assert r["confidence_score"] == 40

    def test_ip_sem_a_reprovado(self):
        r = run(self._ip(dns={"A": [], "PTR": []}))
        assert r["approved"] is False

    # --- IPs pulam checks de domínio ---

    def test_ip_pula_domain_format(self):
        r = run(self._ip())
        assert r["checks"]["domain_format"]["reason"] == "N/A para IPs"
        assert r["checks"]["domain_format"]["score"] == 0

    def test_ip_pula_whois(self):
        r = run(self._ip())
        assert r["checks"]["whois"]["reason"] == "N/A para IPs"
        assert r["checks"]["whois"]["score"] == 0

    # --- Schema do resultado ---

    def test_resultado_contem_chaves_obrigatorias(self):
        r = run(self._dominio())
        obrigatorias = {
            "target", "is_ip", "target_type", "confidence_score",
            "integrity_ok", "approved", "checks", "warnings",
        }
        assert obrigatorias.issubset(r.keys())

    def test_target_populado_para_dominio(self):
        r = run(self._dominio(domain="target.com"))
        assert r["target"] == "target.com"

    def test_target_populado_para_ip(self):
        r = run(self._ip(ip="1.1.1.1"))
        assert r["target"] == "1.1.1.1"
