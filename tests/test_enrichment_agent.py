"""
tests/test_enrichment_agent.py — Testes unitários do enrichment_agent.py

Cobertura:
  - _mask_url: redação de API keys em URLs e strings de erro
  - fetch_subdomains: resposta ok, exceção, wildcards filtrados
  - fetch_shodan_full: ok, 404, 401, sem key, exceção
  - fetch_http_fingerprint: HTTPS ok, fallback HTTP, ambos falhando
  - fetch_ssl_info: certificado ok, exceção
  - fetch_virustotal: ok (domínio e IP), 404, sem key
  - fetch_abuseipdb: ok, IP inválido, sem key
  - fetch_ipinfo: ok, sem token, exceção
  - _build_summary: deduplicação de CVEs, truncamento, portas, headers
  - run: integração dos mocks — zero rede real

Estratégia: unittest.mock.patch no módulo agents.enrichment_agent
para interceptar requests.get e socket antes de qualquer I/O.
"""

import pytest
import socket
import ssl
from unittest.mock import patch, MagicMock, call
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Importação segura — variáveis de ambiente zeradas antes do import
# ---------------------------------------------------------------------------

import os
os.environ.setdefault("SHODAN_API_KEY", "")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
os.environ.setdefault("ABUSEIPDB_API_KEY", "")
os.environ.setdefault("IPINFO_TOKEN", "")

from agents.enrichment_agent import (
    _mask_url,
    fetch_subdomains,
    fetch_shodan_full,
    fetch_http_fingerprint,
    fetch_ssl_info,
    fetch_virustotal,
    fetch_abuseipdb,
    fetch_ipinfo,
    _build_summary,
    run,
)


# ---------------------------------------------------------------------------
# Helpers de mock
# ---------------------------------------------------------------------------

def _mock_response(json_data: dict | list, status_code: int = 200) -> MagicMock:
    """Cria mock de requests.Response com json() e status_code configurados."""
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data
    m.headers = {}
    m.history = []
    m.url = "https://mock.test"
    # raise_for_status não faz nada em 200; para 4xx/5xx levanta exceção
    if status_code >= 400:
        m.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    else:
        m.raise_for_status.return_value = None
    return m


# ---------------------------------------------------------------------------
# Fixtures — dados de entrada
# ---------------------------------------------------------------------------

@pytest.fixture
def domain_collected() -> dict:
    return {
        "domain": "example.com",
        "is_ip": False,
        "dns": {"A": ["93.184.216.34"]},
        "whois": {"skipped": False, "registrar": "ICANN"},
    }


@pytest.fixture
def ip_collected() -> dict:
    return {
        "ip": "45.33.32.156",
        "is_ip": True,
        "dns": {"A": ["45.33.32.156"]},
        "whois": {"skipped": True},
    }


@pytest.fixture
def crt_sh_response() -> list:
    """Resposta simulada do crt.sh com duplicatas e wildcards."""
    return [
        {"name_value": "mail.example.com"},
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "*.example.com"},      # deve ser filtrado
        {"name_value": "example.com"},         # deve ser filtrado (== domain)
        {"name_value": "mail.example.com"},    # duplicata — só deve aparecer uma vez
    ]


@pytest.fixture
def shodan_response() -> dict:
    return {
        "org": "ACME Corp",
        "isp": "ACME ISP",
        "asn": "AS12345",
        "country_name": "Brazil",
        "city": "São Paulo",
        "os": None,
        "ports": [22, 80, 443],
        "hostnames": ["scanme.nmap.org"],
        "tags": [],
        "last_update": "2024-01-01",
        "vulns": {"CVE-2021-41773": {}, "CVE-2022-1388": {}},
        "data": [
            {
                "port": 80,
                "transport": "tcp",
                "data": "HTTP/1.1 200 OK",
                "product": "Apache",
                "version": "2.4.49",
                "cpe": ["cpe:2.3:a:apache:http_server:2.4.49"],
                "vulns": {"CVE-2021-41773": {}},
            }
        ],
    }


@pytest.fixture
def vt_domain_response() -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10,
                },
                "reputation": -5,
                "categories": {"Forcepoint ThreatSeeker": "malware sites"},
                "tags": ["malware"],
                "last_analysis_date": 1700000000,
            }
        }
    }


@pytest.fixture
def abuse_response() -> dict:
    return {
        "data": {
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "numDistinctUsers": 15,
            "lastReportedAt": "2024-01-15T10:00:00Z",
            "countryCode": "CN",
            "isp": "ChinaTelecom",
            "domain": "ctinco.net",
            "isTor": False,
            "isPublic": True,
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }


@pytest.fixture
def ipinfo_response() -> dict:
    return {
        "ip": "45.33.32.156",
        "hostname": "scanme.nmap.org",
        "org": "AS63949 Akamai Technologies",
        "city": "Fremont",
        "region": "California",
        "country": "US",
        "loc": "37.5483,-121.9886",
        "timezone": "America/Los_Angeles",
    }


# ---------------------------------------------------------------------------
# _mask_url
# ---------------------------------------------------------------------------

class TestMaskUrl:
    def test_masks_key_param(self):
        url = "https://api.shodan.io/shodan/host/1.2.3.4?key=MYSECRETKEY123"
        result = _mask_url(url)
        assert "MYSECRETKEY123" not in result
        assert "***REDACTED***" in result

    def test_masks_token_param(self):
        url = "https://ipinfo.io/1.2.3.4/json?token=abc123xyz"
        result = _mask_url(url)
        assert "abc123xyz" not in result

    def test_masks_api_key_param(self):
        url = "https://api.example.com/data?api_key=supersecret&other=val"
        result = _mask_url(url)
        assert "supersecret" not in result
        assert "other=val" in result  # parâmetro não sensível preservado

    def test_masks_apikey_param(self):
        url = "https://example.com?apikey=12345abcde"
        result = _mask_url(url)
        assert "12345abcde" not in result

    def test_no_sensitive_params_unchanged(self):
        url = "https://crt.sh/?q=%.example.com&output=json"
        assert _mask_url(url) == url

    def test_empty_string(self):
        assert _mask_url("") == ""

    def test_masks_in_error_message(self):
        msg = "Connection failed: https://api.shodan.io/host/1.2.3.4?key=SECRET"
        result = _mask_url(msg)
        assert "SECRET" not in result


# ---------------------------------------------------------------------------
# fetch_subdomains
# ---------------------------------------------------------------------------

class TestFetchSubdomains:
    @patch("agents.enrichment_agent.requests.get")
    def test_returns_sorted_unique_subdomains(self, mock_get, crt_sh_response):
        mock_get.return_value = _mock_response(crt_sh_response)
        result = fetch_subdomains("example.com")

        assert result["count"] == 3
        assert "mail.example.com" in result["subdomains"]
        assert "www.example.com" in result["subdomains"]
        assert "api.example.com" in result["subdomains"]

    @patch("agents.enrichment_agent.requests.get")
    def test_wildcards_are_filtered(self, mock_get, crt_sh_response):
        mock_get.return_value = _mock_response(crt_sh_response)
        result = fetch_subdomains("example.com")
        assert all(not s.startswith("*") for s in result["subdomains"])

    @patch("agents.enrichment_agent.requests.get")
    def test_root_domain_excluded(self, mock_get, crt_sh_response):
        mock_get.return_value = _mock_response(crt_sh_response)
        result = fetch_subdomains("example.com")
        assert "example.com" not in result["subdomains"]

    @patch("agents.enrichment_agent.requests.get")
    def test_deduplicates_subdomains(self, mock_get, crt_sh_response):
        mock_get.return_value = _mock_response(crt_sh_response)
        result = fetch_subdomains("example.com")
        assert len(result["subdomains"]) == len(set(result["subdomains"]))

    @patch("agents.enrichment_agent.requests.get")
    def test_network_failure_returns_empty(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        result = fetch_subdomains("example.com")
        assert result["subdomains"] == []
        assert result["count"] == 0
        assert "error" in result

    @patch("agents.enrichment_agent.requests.get")
    def test_empty_crtsh_response(self, mock_get):
        mock_get.return_value = _mock_response([])
        result = fetch_subdomains("example.com")
        assert result["count"] == 0
        assert result["subdomains"] == []

    @patch("agents.enrichment_agent.requests.get")
    def test_source_is_crtsh(self, mock_get, crt_sh_response):
        mock_get.return_value = _mock_response(crt_sh_response)
        result = fetch_subdomains("example.com")
        assert result["source"] == "crt.sh"


# ---------------------------------------------------------------------------
# fetch_shodan_full
# ---------------------------------------------------------------------------

class TestFetchShodanFull:
    def test_returns_skipped_when_no_key(self):
        with patch.dict(os.environ, {"SHODAN_API_KEY": ""}):
            import importlib, agents.enrichment_agent as ea
            ea.SHODAN_KEY = ""
            result = fetch_shodan_full("1.2.3.4")
        assert result.get("skipped") is True

    @patch("agents.enrichment_agent.requests.get")
    def test_successful_response_structure(self, mock_get, shodan_response):
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = "FAKEKEY"
        mock_get.return_value = _mock_response(shodan_response)

        result = fetch_shodan_full("45.33.32.156")

        assert result["org"] == "ACME Corp"
        assert result["asn"] == "AS12345"
        assert result["source"] == "shodan_api"
        assert isinstance(result["services"], list)
        assert isinstance(result["all_cves"], list)
        assert "CVE-2021-41773" in result["all_cves"]
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_404_returns_not_indexed_error(self, mock_get):
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = "FAKEKEY"
        mock_get.return_value = _mock_response({}, status_code=404)
        mock_get.return_value.raise_for_status.side_effect = None

        result = fetch_shodan_full("1.2.3.4")
        assert "não indexado" in result.get("error", "")
        ea.SHODAN_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_401_returns_invalid_key_error(self, mock_get):
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = "BADKEY"
        resp = _mock_response({}, status_code=401)
        resp.raise_for_status.side_effect = None
        mock_get.return_value = resp

        result = fetch_shodan_full("1.2.3.4")
        assert "inválida" in result.get("error", "")
        ea.SHODAN_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_exception_returns_error_without_key_leak(self, mock_get):
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = "SUPERSECRETKEY"
        mock_get.side_effect = Exception(f"https://api.shodan.io?key=SUPERSECRETKEY failed")

        result = fetch_shodan_full("1.2.3.4")
        assert "error" in result
        # A key não deve aparecer no resultado retornado ao pipeline
        assert "SUPERSECRETKEY" not in str(result)
        ea.SHODAN_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_vulns_as_list_normalized(self, mock_get, shodan_response):
        """Shodan às vezes retorna vulns como lista — deve normalizar para list[str]."""
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = "FAKEKEY"
        shodan_response["vulns"] = ["CVE-2021-41773", "CVE-2022-1388"]
        mock_get.return_value = _mock_response(shodan_response)

        result = fetch_shodan_full("1.2.3.4")
        assert isinstance(result["all_cves"], list)
        assert "CVE-2021-41773" in result["all_cves"]
        ea.SHODAN_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_service_banner_truncated_to_300(self, mock_get, shodan_response):
        import agents.enrichment_agent as ea
        ea.SHODAN_KEY = "FAKEKEY"
        shodan_response["data"][0]["data"] = "X" * 500
        mock_get.return_value = _mock_response(shodan_response)

        result = fetch_shodan_full("1.2.3.4")
        for svc in result["services"]:
            assert len(svc["banner"]) <= 300
        ea.SHODAN_KEY = ""


# ---------------------------------------------------------------------------
# fetch_http_fingerprint
# ---------------------------------------------------------------------------

class TestFetchHttpFingerprint:
    @patch("agents.enrichment_agent.requests.get")
    def test_detects_server_header(self, mock_get):
        resp = _mock_response({})
        resp.headers = {"Server": "nginx/1.18", "Content-Type": "text/html"}
        resp.status_code = 200
        resp.url = "https://example.com"
        resp.history = []
        mock_get.return_value = resp

        result = fetch_http_fingerprint("example.com")
        assert result["server"] == "nginx/1.18"
        assert any("nginx" in t.lower() for t in result["tech_stack"])

    @patch("agents.enrichment_agent.requests.get")
    def test_detects_cloudflare_cdn(self, mock_get):
        resp = _mock_response({})
        resp.headers = {"cf-ray": "abc123-GRU", "Server": "cloudflare"}
        resp.status_code = 200
        resp.url = "https://example.com"
        resp.history = []
        mock_get.return_value = resp

        result = fetch_http_fingerprint("example.com")
        assert result.get("cdn") == "Cloudflare"

    @patch("agents.enrichment_agent.requests.get")
    def test_detects_missing_security_headers(self, mock_get):
        resp = _mock_response({})
        resp.headers = {"Content-Type": "text/html"}  # sem nenhum header de segurança
        resp.status_code = 200
        resp.url = "https://example.com"
        resp.history = []
        mock_get.return_value = resp

        result = fetch_http_fingerprint("example.com")
        missing = result.get("missing_security_headers", [])
        assert "HSTS" in missing
        assert "CSP" in missing

    @patch("agents.enrichment_agent.requests.get")
    def test_ssl_error_triggers_http_fallback(self, mock_get):
        import requests as req_lib
        # Primeiro call (HTTPS) levanta SSLError, segundo (HTTP) ok
        resp_ok = _mock_response({})
        resp_ok.headers = {}
        resp_ok.status_code = 200
        resp_ok.url = "http://example.com"
        resp_ok.history = []

        mock_get.side_effect = [
            req_lib.exceptions.SSLError("cert failed"),
            resp_ok,
        ]
        result = fetch_http_fingerprint("example.com")
        assert result.get("ssl_error") is True
        assert result.get("status_code") == 200

    @patch("agents.enrichment_agent.requests.get")
    def test_both_protocols_fail(self, mock_get):
        import requests as req_lib
        mock_get.side_effect = [
            req_lib.exceptions.SSLError("ssl fail"),
            Exception("http fail too"),
        ]
        result = fetch_http_fingerprint("example.com")
        assert "error" in result

    @patch("agents.enrichment_agent.requests.get")
    def test_headers_normalized_to_lowercase(self, mock_get):
        resp = _mock_response({})
        resp.headers = {"X-Powered-By": "PHP/8.1", "Server": "Apache"}
        resp.status_code = 200
        resp.url = "https://example.com"
        resp.history = []
        mock_get.return_value = resp

        result = fetch_http_fingerprint("example.com")
        assert "x-powered-by" in result["headers"]
        assert "server" in result["headers"]


# ---------------------------------------------------------------------------
# fetch_ssl_info
# ---------------------------------------------------------------------------

class TestFetchSslInfo:
    def _make_cert(self) -> dict:
        """Certificado mínimo válido para os testes."""
        future = "Dec 31 23:59:59 2099 GMT"
        return {
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
            "issuer": [[("organizationName", "Let's Encrypt"), ("commonName", "R3")]],
            "subject": [[("commonName", "example.com")]],
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": future,
        }

    @patch("agents.enrichment_agent.ssl.create_default_context")
    @patch("agents.enrichment_agent.socket.create_connection")
    def test_extracts_sans(self, mock_conn, mock_ctx):
        cert = self._make_cert()
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.__enter__ = MagicMock(return_value=mock_ssl_sock)
        mock_ssl_sock.__exit__ = MagicMock(return_value=False)

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock

        mock_ctx.return_value.wrap_socket.return_value = mock_ssl_sock

        result = fetch_ssl_info("example.com")
        assert "example.com" in result["sans"]
        assert "www.example.com" in result["sans"]
        assert result["san_count"] == 2

    @patch("agents.enrichment_agent.ssl.create_default_context")
    @patch("agents.enrichment_agent.socket.create_connection")
    def test_wildcard_detected(self, mock_conn, mock_ctx):
        cert = self._make_cert()
        cert["subjectAltName"].append(("DNS", "*.example.com"))
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = cert
        mock_ssl_sock.__enter__ = MagicMock(return_value=mock_ssl_sock)
        mock_ssl_sock.__exit__ = MagicMock(return_value=False)

        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock

        mock_ctx.return_value.wrap_socket.return_value = mock_ssl_sock

        result = fetch_ssl_info("example.com")
        assert result["is_wildcard"] is True

    @patch("agents.enrichment_agent.socket.create_connection")
    def test_connection_failure_returns_error(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError("port 443 closed")
        result = fetch_ssl_info("example.com")
        assert "error" in result


# ---------------------------------------------------------------------------
# fetch_virustotal
# ---------------------------------------------------------------------------

class TestFetchVirusTotal:
    def test_returns_skipped_when_no_key(self):
        import agents.enrichment_agent as ea
        ea.VT_KEY = ""
        result = fetch_virustotal("example.com")
        assert result.get("skipped") is True

    @patch("agents.enrichment_agent.requests.get")
    def test_domain_flagged(self, mock_get, vt_domain_response):
        import agents.enrichment_agent as ea
        ea.VT_KEY = "FAKEKEY"
        mock_get.return_value = _mock_response(vt_domain_response)

        result = fetch_virustotal("example.com")
        assert result["malicious"] == 3
        assert result["suspicious"] == 1
        assert result["is_flagged"] is True
        assert result["threat_score"] == 4
        ea.VT_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_ip_uses_ip_addresses_endpoint(self, mock_get, vt_domain_response):
        import agents.enrichment_agent as ea
        ea.VT_KEY = "FAKEKEY"
        mock_get.return_value = _mock_response(vt_domain_response)

        fetch_virustotal("1.2.3.4")
        called_url = mock_get.call_args[0][0]
        assert "ip_addresses" in called_url
        ea.VT_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_domain_uses_domains_endpoint(self, mock_get, vt_domain_response):
        import agents.enrichment_agent as ea
        ea.VT_KEY = "FAKEKEY"
        mock_get.return_value = _mock_response(vt_domain_response)

        fetch_virustotal("example.com")
        called_url = mock_get.call_args[0][0]
        assert "domains" in called_url
        ea.VT_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_404_returns_not_found_error(self, mock_get):
        import agents.enrichment_agent as ea
        ea.VT_KEY = "FAKEKEY"
        resp = _mock_response({}, status_code=404)
        resp.raise_for_status.side_effect = None
        mock_get.return_value = resp

        result = fetch_virustotal("notfound.io")
        assert "error" in result
        ea.VT_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_clean_domain_not_flagged(self, mock_get):
        import agents.enrichment_agent as ea
        ea.VT_KEY = "FAKEKEY"
        clean_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "harmless": 75, "undetected": 5
                    },
                    "reputation": 10,
                    "categories": {}, "tags": [], "last_analysis_date": "",
                }
            }
        }
        mock_get.return_value = _mock_response(clean_response)
        result = fetch_virustotal("google.com")
        assert result["is_flagged"] is False
        ea.VT_KEY = ""


# ---------------------------------------------------------------------------
# fetch_abuseipdb
# ---------------------------------------------------------------------------

class TestFetchAbuseIPDB:
    def test_returns_skipped_when_no_key(self):
        import agents.enrichment_agent as ea
        ea.ABUSEIPDB_KEY = ""
        result = fetch_abuseipdb("1.2.3.4")
        assert result.get("skipped") is True

    @patch("agents.enrichment_agent.requests.get")
    def test_high_score_flagged_as_abusive(self, mock_get, abuse_response):
        import agents.enrichment_agent as ea
        ea.ABUSEIPDB_KEY = "FAKEKEY"
        mock_get.return_value = _mock_response(abuse_response)

        result = fetch_abuseipdb("1.2.3.4")
        assert result["abuse_score"] == 87
        assert result["is_abusive"] is True
        assert result["total_reports"] == 42
        ea.ABUSEIPDB_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_low_score_not_abusive(self, mock_get):
        import agents.enrichment_agent as ea
        ea.ABUSEIPDB_KEY = "FAKEKEY"
        clean = {"data": {
            "abuseConfidenceScore": 10, "totalReports": 2,
            "numDistinctUsers": 1, "lastReportedAt": "",
            "countryCode": "US", "isp": "Cloudflare",
            "domain": "cloudflare.com", "isTor": False,
            "isPublic": True, "usageType": "Content Delivery Network"
        }}
        mock_get.return_value = _mock_response(clean)
        result = fetch_abuseipdb("1.1.1.1")
        assert result["is_abusive"] is False
        ea.ABUSEIPDB_KEY = ""

    def test_domain_input_returns_skipped(self):
        """AbuseIPDB é só para IPs — domínio deve retornar skipped."""
        import agents.enrichment_agent as ea
        ea.ABUSEIPDB_KEY = "FAKEKEY"
        result = fetch_abuseipdb("example.com")
        assert result.get("skipped") is True
        ea.ABUSEIPDB_KEY = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_network_failure_returns_error(self, mock_get):
        import agents.enrichment_agent as ea
        ea.ABUSEIPDB_KEY = "FAKEKEY"
        mock_get.side_effect = Exception("timeout")
        result = fetch_abuseipdb("1.2.3.4")
        assert "error" in result
        ea.ABUSEIPDB_KEY = ""


# ---------------------------------------------------------------------------
# fetch_ipinfo
# ---------------------------------------------------------------------------

class TestFetchIPInfo:
    @patch("agents.enrichment_agent.requests.get")
    def test_successful_response(self, mock_get, ipinfo_response):
        mock_get.return_value = _mock_response(ipinfo_response)
        result = fetch_ipinfo("45.33.32.156")

        assert result["hostname"] == "scanme.nmap.org"
        assert result["country"] == "US"
        assert result["source"] == "ipinfo"

    @patch("agents.enrichment_agent.requests.get")
    def test_asn_extracted_from_org(self, mock_get, ipinfo_response):
        mock_get.return_value = _mock_response(ipinfo_response)
        result = fetch_ipinfo("45.33.32.156")
        assert result["asn"] == "AS63949"

    @patch("agents.enrichment_agent.requests.get")
    def test_token_included_when_configured(self, mock_get, ipinfo_response):
        import agents.enrichment_agent as ea
        ea.IPINFO_TOKEN = "mytoken123"
        mock_get.return_value = _mock_response(ipinfo_response)

        fetch_ipinfo("1.2.3.4")
        call_kwargs = mock_get.call_args[1]
        assert "token" in call_kwargs.get("params", {})
        ea.IPINFO_TOKEN = ""

    @patch("agents.enrichment_agent.requests.get")
    def test_network_failure_returns_error(self, mock_get):
        mock_get.side_effect = Exception("connection refused")
        result = fetch_ipinfo("1.2.3.4")
        assert "error" in result

    @patch("agents.enrichment_agent.requests.get")
    def test_empty_org_asn_is_empty_string(self, mock_get, ipinfo_response):
        ipinfo_response["org"] = ""
        mock_get.return_value = _mock_response(ipinfo_response)
        result = fetch_ipinfo("1.2.3.4")
        assert result["asn"] == ""


# ---------------------------------------------------------------------------
# _build_summary — lógica pura, zero mock
# ---------------------------------------------------------------------------

class TestBuildSummary:
    def _base_result(self) -> dict:
        """Estrutura mínima que _build_summary espera."""
        return {
            "sources": {
                "infra_agent": {},
                "subdomains": {"count": 0, "subdomains": []},
                "ssl": {},
                "http": {},
                "virustotal": {},
                "shodan": [{}],
                "abuseipdb": [{}],
                "ipinfo": [{}],
            }
        }

    def test_subdomain_count(self):
        result = self._base_result()
        result["sources"]["subdomains"] = {
            "count": 5,
            "subdomains": ["a.x.com", "b.x.com", "c.x.com", "d.x.com", "e.x.com"]
        }
        summary = _build_summary(result)
        assert summary["subdomain_count"] == 5

    def test_cves_deduplication(self):
        """CVEs do infra_agent e Shodan devem ser deduplicados."""
        result = self._base_result()
        result["sources"]["infra_agent"] = {"vulns": ["CVE-001", "CVE-002"]}
        result["sources"]["shodan"] = [{"all_cves": ["CVE-002", "CVE-003"]}]

        summary = _build_summary(result)
        assert summary["total_cves"] == 3  # 001, 002, 003 — sem duplicata
        assert len(set(summary["cves"])) == len(summary["cves"])

    def test_cves_truncated_to_max(self):
        """CVEs não devem exceder _MAX_CVES_FOR_LLM = 15."""
        result = self._base_result()
        many_cves = [f"CVE-2024-{i:04d}" for i in range(50)]
        result["sources"]["infra_agent"] = {"vulns": many_cves}

        summary = _build_summary(result)
        assert summary["total_cves"] == 50   # total real
        assert len(summary["cves"]) == 15    # truncado para o LLM

    def test_total_cves_reflects_real_count(self):
        """total_cves deve refletir todos os CVEs, não o truncado."""
        result = self._base_result()
        result["sources"]["infra_agent"] = {"cves": [f"CVE-{i}" for i in range(30)]}

        summary = _build_summary(result)
        assert summary["total_cves"] == 30
        assert len(summary["cves"]) <= 15

    def test_vt_flagged_true(self):
        result = self._base_result()
        result["sources"]["virustotal"] = {
            "is_flagged": True, "malicious": 5, "threat_score": 5
        }
        summary = _build_summary(result)
        assert summary["vt_flagged"] is True
        assert summary["vt_malicious"] == 5

    def test_max_abuse_score_from_multiple_ips(self):
        """Deve pegar o maior score entre todos os IPs."""
        result = self._base_result()
        result["sources"]["abuseipdb"] = [
            {"abuse_score": 10},
            {"abuse_score": 87},
            {"abuse_score": 45},
        ]
        summary = _build_summary(result)
        assert summary["max_abuse_score"] == 87
        assert summary["has_abusive_ip"] is True

    def test_abuse_score_below_threshold_not_abusive(self):
        result = self._base_result()
        result["sources"]["abuseipdb"] = [{"abuse_score": 20}]
        summary = _build_summary(result)
        assert summary["has_abusive_ip"] is False

    def test_ssl_expiring_soon(self):
        result = self._base_result()
        result["sources"]["ssl"] = {
            "expiring_soon": True, "expired": False, "is_wildcard": False, "sans": []
        }
        summary = _build_summary(result)
        assert summary["ssl_expiring_soon"] is True
        assert summary["ssl_expired"] is False

    def test_missing_security_headers_from_http(self):
        result = self._base_result()
        result["sources"]["http"] = {
            "missing_security_headers": ["HSTS", "CSP", "X-Frame-Options"],
            "server": "Apache/2.4.49",
            "tech_stack": ["Server: Apache/2.4.49"],
        }
        summary = _build_summary(result)
        assert "HSTS" in summary["missing_security_headers"]
        assert summary["server_banner"] == "Apache/2.4.49"

    def test_exposed_services_merged_infra_and_shodan(self):
        """Portas sem produto (infra_agent) + produto/versão (Shodan) devem ser mescladas."""
        result = self._base_result()
        result["sources"]["infra_agent"] = {"open_ports": [22, 80, 443]}
        result["sources"]["shodan"] = [{
            "services": [
                {"port": 80, "product": "Apache", "version": "2.4.49", "cves": ["CVE-2021-41773"]}
            ],
            "all_cves": []
        }]
        summary = _build_summary(result)
        ports_in_summary = [s["port"] for s in summary["exposed_services"]]
        assert 22 in ports_in_summary
        assert 80 in ports_in_summary
        assert 443 in ports_in_summary

        apache_svc = next(s for s in summary["exposed_services"] if s["port"] == 80)
        assert apache_svc["product"] == "Apache"

    def test_infra_cves_from_cves_key(self):
        """infra_agent pode usar 'cves' em vez de 'vulns' — ambos devem funcionar."""
        result = self._base_result()
        result["sources"]["infra_agent"] = {"cves": ["CVE-AAA", "CVE-BBB"]}
        summary = _build_summary(result)
        assert summary["total_cves"] == 2


# ---------------------------------------------------------------------------
# run — integração com todos os fetchers mockados
# ---------------------------------------------------------------------------

class TestRun:
    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_domain_run_calls_all_sources(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        domain_collected,
    ):
        mock_subs.return_value   = {"subdomains": [], "count": 0}
        mock_ssl.return_value    = {}
        mock_http.return_value   = {}
        mock_vt.return_value     = {}
        mock_shodan.return_value = {}
        mock_abuse.return_value  = {}
        mock_ipinfo.return_value = {}

        result = run(domain_collected, ips=["93.184.216.34"])

        mock_subs.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_http.assert_called_once_with("example.com")
        mock_vt.assert_called_once_with("example.com")
        mock_shodan.assert_called_once_with("93.184.216.34")
        mock_abuse.assert_called_once_with("93.184.216.34")
        mock_ipinfo.assert_called_once_with("93.184.216.34")

    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_ip_target_skips_domain_sources(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        ip_collected,
    ):
        mock_vt.return_value     = {}
        mock_shodan.return_value = {}
        mock_abuse.return_value  = {}
        mock_ipinfo.return_value = {}

        result = run(ip_collected)

        mock_subs.assert_not_called()
        mock_ssl.assert_not_called()
        mock_http.assert_not_called()
        mock_vt.assert_called_once()
        assert result["sources"]["subdomains"]["skipped"] is True

    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_result_has_required_top_level_keys(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        domain_collected,
    ):
        for m in (mock_subs, mock_ssl, mock_http, mock_vt,
                  mock_shodan, mock_abuse, mock_ipinfo):
            m.return_value = {}

        result = run(domain_collected, ips=["93.184.216.34"])

        for key in ("target", "is_ip", "enriched_at", "sources", "summary"):
            assert key in result

    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_one_source_failing_does_not_crash_run(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        domain_collected,
    ):
        """Pipeline deve concluir mesmo que uma fonte exploda com exceção."""
        mock_subs.side_effect  = Exception("crt.sh fora do ar")
        mock_ssl.return_value  = {}
        mock_http.return_value = {}
        mock_vt.return_value   = {}
        mock_shodan.return_value = {}
        mock_abuse.return_value  = {}
        mock_ipinfo.return_value = {}

        # fetch_subdomains explodindo deve fazer run() retornar com erro em sources
        # MAS não deve levantar exceção para o caller
        try:
            result = run(domain_collected, ips=["93.184.216.34"])
        except Exception:
            pytest.fail("run() não deve propagar exceções de fontes individuais")

    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_infra_data_registered_in_sources(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        domain_collected,
    ):
        for m in (mock_subs, mock_ssl, mock_http, mock_vt,
                  mock_shodan, mock_abuse, mock_ipinfo):
            m.return_value = {}

        infra = {"open_ports": [22, 80], "vulns": ["CVE-001"]}
        result = run(domain_collected, ips=["93.184.216.34"], infra_data=infra)

        assert result["sources"]["infra_agent"] == infra

    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_ips_extracted_from_collected_when_not_passed(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        domain_collected,
    ):
        """Quando ips=None, deve extrair de dns.A do collected_data."""
        for m in (mock_subs, mock_ssl, mock_http, mock_vt,
                  mock_shodan, mock_abuse, mock_ipinfo):
            m.return_value = {}

        run(domain_collected)  # ips=None — deve usar dns.A = ["93.184.216.34"]

        mock_shodan.assert_called_once_with("93.184.216.34")

    @patch("agents.enrichment_agent.fetch_ipinfo")
    @patch("agents.enrichment_agent.fetch_abuseipdb")
    @patch("agents.enrichment_agent.fetch_shodan_full")
    @patch("agents.enrichment_agent.fetch_virustotal")
    @patch("agents.enrichment_agent.fetch_http_fingerprint")
    @patch("agents.enrichment_agent.fetch_ssl_info")
    @patch("agents.enrichment_agent.fetch_subdomains")
    def test_multiple_ips_calls_per_ip_sources(
        self, mock_subs, mock_ssl, mock_http, mock_vt,
        mock_shodan, mock_abuse, mock_ipinfo,
        domain_collected,
    ):
        """Com 2 IPs, Shodan/AbuseIPDB/IPInfo devem ser chamados 2 vezes cada."""
        for m in (mock_subs, mock_ssl, mock_http, mock_vt,
                  mock_shodan, mock_abuse, mock_ipinfo):
            m.return_value = {}

        run(domain_collected, ips=["1.1.1.1", "2.2.2.2"])

        assert mock_shodan.call_count == 2
        assert mock_abuse.call_count == 2
        assert mock_ipinfo.call_count == 2
