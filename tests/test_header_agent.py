"""
tests/test_header_agent.py — Cobertura completa do header_agent.py

Cobre:
  - _check_cors: wildcard vs origem específica vs ausente
  - _check_cookies: todas as combinações de flags Secure/HttpOnly/SameSite
  - run(): HTTPS sucesso, fallback HTTP (SSLError / ConnectionError / Timeout),
           falha total, detecção de headers ausentes, info leakage, CORS, cookies
  - REGRESSÃO CRÍTICA: result['error'] deve existir como None (não ausente)
    quando não há erro — consumidor usa .get('error'), não 'error' in result.

Nenhum teste faz requisição real. Todo I/O de rede é mockado via unittest.mock.

Execute:
    pytest tests/test_header_agent.py -v
"""

import pytest
import requests
from unittest.mock import MagicMock, patch

from agents.header_agent import _check_cookies, _check_cors, run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_resp(status_code: int = 200, headers: dict | None = None, url: str = "https://example.com") -> MagicMock:
    """Cria um MagicMock que simula requests.Response."""
    m = MagicMock()
    m.status_code = status_code
    m.headers = headers or {}
    m.url = url
    return m


# Conjunto completo de security headers — nenhum finding de "ausente" esperado
_TODOS_SECURITY_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "cache-control": "no-store",
}

# Quantos security headers estão definidos em SECURITY_HEADERS do agente
_N_SECURITY_HEADERS = 7


# ---------------------------------------------------------------------------
# _check_cors
# ---------------------------------------------------------------------------

class TestCheckCors:

    def test_wildcard_gera_finding(self):
        r = _check_cors({"access-control-allow-origin": "*"})
        assert r is not None
        assert r["type"] == "cors_wildcard"
        assert r["severity"] == "MEDIUM"
        assert r["mitre_id"] == "T1190"

    def test_origem_especifica_nao_flaggea(self):
        r = _check_cors({"access-control-allow-origin": "https://example.com"})
        assert r is None

    def test_sem_header_cors(self):
        r = _check_cors({})
        assert r is None

    def test_wildcard_parcial_nao_flaggea(self):
        # "https://*.example.com" não é "*" exato — não deve gerar finding
        r = _check_cors({"access-control-allow-origin": "https://*.example.com"})
        assert r is None

    def test_finding_contem_evidence(self):
        r = _check_cors({"access-control-allow-origin": "*"})
        assert "evidence" in r
        assert "*" in r["evidence"]


# ---------------------------------------------------------------------------
# _check_cookies
# ---------------------------------------------------------------------------

class TestCheckCookies:

    def test_sem_set_cookie_retorna_vazio(self):
        assert _check_cookies({}) == []

    def test_todas_flags_presentes_retorna_vazio(self):
        headers = {"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"}
        assert _check_cookies(headers) == []

    def test_sem_secure_gera_finding(self):
        headers = {"set-cookie": "session=abc; HttpOnly; SameSite=Strict"}
        tipos = [f["type"] for f in _check_cookies(headers)]
        assert "cookie_no_secure" in tipos

    def test_sem_httponly_gera_finding(self):
        headers = {"set-cookie": "session=abc; Secure; SameSite=Lax"}
        tipos = [f["type"] for f in _check_cookies(headers)]
        assert "cookie_no_httponly" in tipos

    def test_sem_samesite_gera_finding(self):
        headers = {"set-cookie": "session=abc; Secure; HttpOnly"}
        tipos = [f["type"] for f in _check_cookies(headers)]
        assert "cookie_no_samesite" in tipos

    def test_sem_nenhuma_flag_gera_3_findings(self):
        headers = {"set-cookie": "session=abc"}
        findings = _check_cookies(headers)
        assert len(findings) == 3

    def test_findings_contem_mitre_e_severity(self):
        headers = {"set-cookie": "session=abc"}
        for f in _check_cookies(headers):
            assert "mitre_id" in f
            assert "severity" in f
            assert "title" in f
            assert "recommendation" in f

    def test_severity_cookie_no_secure_e_medium(self):
        headers = {"set-cookie": "tok=xyz"}
        findings = {f["type"]: f for f in _check_cookies(headers)}
        assert findings["cookie_no_secure"]["severity"] == "MEDIUM"

    def test_severity_cookie_no_samesite_e_low(self):
        headers = {"set-cookie": "tok=xyz"}
        findings = {f["type"]: f for f in _check_cookies(headers)}
        assert findings["cookie_no_samesite"]["severity"] == "LOW"


# ---------------------------------------------------------------------------
# run() — todos os testes com mock de requests.get
# ---------------------------------------------------------------------------

class TestRun:

    # ----------------------------------------------------------------
    # REGRESSÃO CRÍTICA — chave 'error' sempre presente
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_regressao_error_key_existe_como_none_em_sucesso(self, mock_get):
        """
        BUG HISTÓRICO: ai_analyst usava 'error' in result → sempre True
        porque 'error' existe como None. Correto é .get('error').
        Este teste garante que a chave 'error' EXISTE mas é None.
        """
        mock_get.return_value = _mock_resp()
        result = run("example.com")

        assert "error" in result           # chave deve existir
        assert result["error"] is None     # mas não deve ter valor

    # ----------------------------------------------------------------
    # Happy path — HTTPS sucesso
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_https_sucesso_sem_findings_ausentes(self, mock_get):
        mock_get.return_value = _mock_resp(headers=_TODOS_SECURITY_HEADERS)
        result = run("example.com")

        ausentes = [f for f in result["findings"] if f["type"].startswith("missing_")]
        assert ausentes == []

    @patch("agents.header_agent.requests.get")
    def test_https_sem_nenhum_security_header_gera_7_findings(self, mock_get):
        mock_get.return_value = _mock_resp(headers={})
        result = run("example.com")

        ausentes = [f for f in result["findings"] if f["type"].startswith("missing_")]
        assert len(ausentes) == _N_SECURITY_HEADERS

    @patch("agents.header_agent.requests.get")
    def test_status_code_capturado(self, mock_get):
        mock_get.return_value = _mock_resp(status_code=403)
        result = run("example.com")
        assert result["status_code"] == 403

    @patch("agents.header_agent.requests.get")
    def test_domain_extraido_de_host_simples(self, mock_get):
        mock_get.return_value = _mock_resp(url="https://example.com")
        result = run("example.com")
        assert result["domain"] == "example.com"

    @patch("agents.header_agent.requests.get")
    def test_domain_extraido_de_url_com_path(self, mock_get):
        mock_get.return_value = _mock_resp(url="https://example.com/path")
        result = run("https://example.com/path")
        assert result["domain"] == "example.com"

    # ----------------------------------------------------------------
    # Info leakage
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_header_server_gera_leakage(self, mock_get):
        mock_get.return_value = _mock_resp(headers={"server": "Apache/2.4.51"})
        result = run("example.com")
        tipos = [f["type"] for f in result["findings"]]
        assert "info_leak_server" in tipos

    @patch("agents.header_agent.requests.get")
    def test_header_x_powered_by_gera_leakage(self, mock_get):
        mock_get.return_value = _mock_resp(headers={"x-powered-by": "PHP/8.1"})
        result = run("example.com")
        tipos = [f["type"] for f in result["findings"]]
        assert "info_leak_x_powered_by" in tipos

    @patch("agents.header_agent.requests.get")
    def test_header_x_aspnet_version_gera_leakage(self, mock_get):
        mock_get.return_value = _mock_resp(headers={"x-aspnet-version": "4.0.30319"})
        result = run("example.com")
        tipos = [f["type"] for f in result["findings"]]
        assert "info_leak_x_aspnet_version" in tipos

    # ----------------------------------------------------------------
    # CORS
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_cors_wildcard_detectado(self, mock_get):
        mock_get.return_value = _mock_resp(headers={"access-control-allow-origin": "*"})
        result = run("example.com")
        tipos = [f["type"] for f in result["findings"]]
        assert "cors_wildcard" in tipos

    # ----------------------------------------------------------------
    # Cookies
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_cookie_sem_flags_gera_3_findings(self, mock_get):
        mock_get.return_value = _mock_resp(headers={"set-cookie": "sess=abc"})
        result = run("example.com")
        tipos = [f["type"] for f in result["findings"]]
        assert "cookie_no_secure" in tipos
        assert "cookie_no_httponly" in tipos
        assert "cookie_no_samesite" in tipos

    # ----------------------------------------------------------------
    # Fallback HTTP
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_fallback_em_ssl_error_adiciona_no_ssl_finding(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.SSLError("SSL handshake failed"),
            _mock_resp(url="http://example.com"),
        ]
        result = run("example.com")

        no_ssl = [f for f in result["findings"] if f["type"] == "no_ssl"]
        assert len(no_ssl) == 1
        assert no_ssl[0]["severity"] == "HIGH"
        assert no_ssl[0]["mitre_id"] == "T1557"

    @patch("agents.header_agent.requests.get")
    def test_fallback_em_connection_error(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("Connection refused"),
            _mock_resp(url="http://example.com"),
        ]
        result = run("example.com")

        no_ssl = [f for f in result["findings"] if f["type"] == "no_ssl"]
        assert len(no_ssl) == 1

    @patch("agents.header_agent.requests.get")
    def test_fallback_em_timeout(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.Timeout("Read timeout"),
            _mock_resp(url="http://example.com"),
        ]
        result = run("example.com")

        no_ssl = [f for f in result["findings"] if f["type"] == "no_ssl"]
        assert len(no_ssl) == 1

    # ----------------------------------------------------------------
    # Falha total (HTTPS + HTTP)
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_falha_total_retorna_error_nao_propaga_excecao(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.SSLError("SSL error"),
            requests.exceptions.RequestException("HTTP also failed"),
        ]
        result = run("example.com")

        assert result.get("error") is not None
        assert result["findings"] == []
        assert result["summary"]["total_findings"] == 0

    # ----------------------------------------------------------------
    # Summary counts
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_summary_total_equals_soma_severidades(self, mock_get):
        mock_get.return_value = _mock_resp(headers={})
        result = run("example.com")
        s = result["summary"]
        soma = s["critical"] + s["high"] + s["medium"] + s["low"] + s["info"]
        assert soma == s["total_findings"]

    @patch("agents.header_agent.requests.get")
    def test_summary_counts_corretos_sem_headers(self, mock_get):
        mock_get.return_value = _mock_resp(headers={})
        result = run("example.com")
        # Com headers vazios: 7 missing (HIGH, MEDIUM×2, LOW×3, INFO×1)
        assert result["summary"]["high"] == 1     # HSTS
        assert result["summary"]["medium"] == 2   # CSP + X-Frame-Options
        assert result["summary"]["low"] == 3      # x-content-type, referrer, permissions
        assert result["summary"]["info"] == 1     # cache-control

    # ----------------------------------------------------------------
    # Schema dos findings
    # ----------------------------------------------------------------

    @patch("agents.header_agent.requests.get")
    def test_findings_contem_chaves_obrigatorias(self, mock_get):
        mock_get.return_value = _mock_resp(headers={})
        result = run("example.com")

        obrigatorias = {"type", "severity", "mitre_id", "mitre_name", "title", "description"}
        for f in result["findings"]:
            assert obrigatorias.issubset(f.keys()), (
                f"Finding '{f.get('type')}' faltando chaves: {obrigatorias - f.keys()}"
            )

    @patch("agents.header_agent.requests.get")
    def test_resultado_contem_chaves_obrigatorias(self, mock_get):
        mock_get.return_value = _mock_resp()
        result = run("example.com")

        obrigatorias = {
            "domain", "target_url", "timestamp", "status_code",
            "error", "findings", "raw_headers", "summary",
        }
        assert obrigatorias.issubset(result.keys())
