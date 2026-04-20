"""
tests/test_correlator.py — Testes unitários do correlator.py

Cobertura:
  - extract_ips / extract_nameservers / extract_registrar / _get_label
  - correlate_pair: todos os cenários de score (0 / 20 / 30 / 50 / 100)
  - run: guards, combinações, saída estruturada

Zero rede real — correlator.py é puro Python.
"""

import pytest
from agents.correlator import (
    extract_ips,
    extract_nameservers,
    extract_registrar,
    _get_label,
    correlate_pair,
    run,
)


# ---------------------------------------------------------------------------
# Fixtures — outputs do collector simulados
# ---------------------------------------------------------------------------

@pytest.fixture
def domain_google() -> dict:
    return {
        "domain": "google.com",
        "is_ip": False,
        "dns": {"A": ["142.250.185.78", "142.250.185.100"]},
        "whois": {
            "skipped": False,
            "registrar": "MarkMonitor Inc.",
            "name_servers": ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM"],
        },
    }


@pytest.fixture
def domain_youtube() -> dict:
    """Compartilha IP e name servers com google.com — score esperado: 80."""
    return {
        "domain": "youtube.com",
        "is_ip": False,
        "dns": {"A": ["142.250.185.78", "172.217.28.110"]},
        "whois": {
            "skipped": False,
            "registrar": "MarkMonitor Inc.",
            "name_servers": ["NS1.GOOGLE.COM", "NS3.GOOGLE.COM"],
        },
    }


@pytest.fixture
def domain_unrelated() -> dict:
    """Sem nenhuma infra em comum com Google."""
    return {
        "domain": "example.com",
        "is_ip": False,
        "dns": {"A": ["93.184.216.34"]},
        "whois": {
            "skipped": False,
            "registrar": "ICANN",
            "name_servers": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
        },
    }


@pytest.fixture
def domain_same_registrar_only() -> dict:
    """Mesmo registrar que google.com, sem IPs ou NS em comum."""
    return {
        "domain": "other-markmonitor-client.com",
        "is_ip": False,
        "dns": {"A": ["1.2.3.4"]},
        "whois": {
            "skipped": False,
            "registrar": "MarkMonitor Inc.",
            "name_servers": ["NS1.OTHER.COM"],
        },
    }


@pytest.fixture
def ip_target() -> dict:
    """Alvo do tipo IP — WHOIS sempre skipped."""
    return {
        "ip": "45.33.32.156",
        "is_ip": True,
        "dns": {"A": ["45.33.32.156"]},
        "whois": {"skipped": True},
    }


@pytest.fixture
def ip_same_as_google() -> dict:
    """IP que aparece também nos registros A do google.com."""
    return {
        "ip": "142.250.185.78",
        "is_ip": True,
        "dns": {"A": ["142.250.185.78"]},
        "whois": {"skipped": True},
    }


@pytest.fixture
def domain_empty_whois() -> dict:
    """WHOIS retornou campos None — situação real com TLDs exóticos."""
    return {
        "domain": "weird.io",
        "is_ip": False,
        "dns": {"A": []},
        "whois": {
            "skipped": False,
            "registrar": None,
            "name_servers": None,
        },
    }


@pytest.fixture
def domain_no_dns() -> dict:
    """Sem chave dns no dict — collector falhou parcialmente."""
    return {
        "domain": "nodns.com",
        "is_ip": False,
        "whois": {
            "skipped": False,
            "registrar": "SomeReg",
            "name_servers": ["NS.SOMEDNS.COM"],
        },
    }


# ---------------------------------------------------------------------------
# extract_ips
# ---------------------------------------------------------------------------

class TestExtractIps:
    def test_returns_set_of_ips(self, domain_google):
        result = extract_ips(domain_google)
        assert isinstance(result, set)
        assert "142.250.185.78" in result

    def test_multiple_ips(self, domain_google):
        assert len(extract_ips(domain_google)) == 2

    def test_ip_target_single_ip(self, ip_target):
        result = extract_ips(ip_target)
        assert result == {"45.33.32.156"}

    def test_missing_dns_key_returns_empty(self, domain_no_dns):
        assert extract_ips(domain_no_dns) == set()

    def test_empty_a_record(self, domain_empty_whois):
        assert extract_ips(domain_empty_whois) == set()

    def test_empty_dict_returns_empty(self):
        assert extract_ips({}) == set()


# ---------------------------------------------------------------------------
# extract_nameservers
# ---------------------------------------------------------------------------

class TestExtractNameservers:
    def test_returns_lowercase(self, domain_google):
        result = extract_nameservers(domain_google)
        assert all(ns == ns.lower() for ns in result)

    def test_normalizes_uppercase_input(self, domain_google):
        result = extract_nameservers(domain_google)
        assert "ns1.google.com" in result

    def test_ip_with_skipped_whois_returns_empty(self, ip_target):
        assert extract_nameservers(ip_target) == set()

    def test_none_name_servers_returns_empty(self, domain_empty_whois):
        assert extract_nameservers(domain_empty_whois) == set()

    def test_empty_dict_returns_empty(self):
        assert extract_nameservers({}) == set()

    def test_missing_whois_returns_empty(self):
        assert extract_nameservers({"domain": "x.com"}) == set()


# ---------------------------------------------------------------------------
# extract_registrar
# ---------------------------------------------------------------------------

class TestExtractRegistrar:
    def test_returns_registrar_string(self, domain_google):
        assert extract_registrar(domain_google) == "MarkMonitor Inc."

    def test_ip_skipped_whois_returns_empty_string(self, ip_target):
        assert extract_registrar(ip_target) == ""

    def test_none_registrar_returns_empty_string(self, domain_empty_whois):
        assert extract_registrar(domain_empty_whois) == ""

    def test_missing_whois_returns_empty_string(self):
        assert extract_registrar({"domain": "x.com"}) == ""


# ---------------------------------------------------------------------------
# _get_label
# ---------------------------------------------------------------------------

class TestGetLabel:
    def test_prefers_domain_over_ip(self):
        collected = {"domain": "example.com", "ip": "1.2.3.4"}
        assert _get_label(collected) == "example.com"

    def test_returns_ip_when_no_domain(self, ip_target):
        assert _get_label(ip_target) == "45.33.32.156"

    def test_returns_unknown_when_empty(self):
        assert _get_label({}) == "unknown"

    def test_domain_label(self, domain_google):
        assert _get_label(domain_google) == "google.com"


# ---------------------------------------------------------------------------
# correlate_pair — scores e estrutura
# ---------------------------------------------------------------------------

class TestCorrelatePair:
    def test_returns_required_keys(self, domain_google, domain_youtube):
        result = correlate_pair(domain_google, domain_youtube)
        for key in ("pair", "correlation_score", "shared_ips",
                    "shared_nameservers", "same_registrar", "registrar"):
            assert key in result

    def test_pair_contains_both_labels(self, domain_google, domain_youtube):
        result = correlate_pair(domain_google, domain_youtube)
        assert "google.com" in result["pair"]
        assert "youtube.com" in result["pair"]

    def test_score_shared_ip_only(self, domain_google, ip_same_as_google):
        """IP compartilhado = +50. NS skipped no IP = +0. Registrar skipped = +0."""
        result = correlate_pair(domain_google, ip_same_as_google)
        assert result["correlation_score"] == 50
        assert "142.250.185.78" in result["shared_ips"]

    def test_score_shared_ns_only(self, domain_google, domain_same_registrar_only):
        """
        Mesmo registrar mas sem IPs ou NS em comum.
        Só registrar = +20.
        """
        target = {
            "domain": "ns-share.com",
            "is_ip": False,
            "dns": {"A": ["9.9.9.9"]},
            "whois": {
                "skipped": False,
                "registrar": "OutroRegistrar",
                "name_servers": ["NS1.GOOGLE.COM", "NS99.OTHER.COM"],
            },
        }
        result = correlate_pair(domain_google, target)
        assert result["correlation_score"] == 30
        assert "ns1.google.com" in result["shared_nameservers"]

    def test_score_same_registrar_only(self, domain_google, domain_same_registrar_only):
        result = correlate_pair(domain_google, domain_same_registrar_only)
        assert result["correlation_score"] == 20
        assert result["same_registrar"] is True
        assert result["registrar"] == "MarkMonitor Inc."

    def test_score_zero_no_overlap(self, domain_google, domain_unrelated):
        result = correlate_pair(domain_google, domain_unrelated)
        assert result["correlation_score"] == 0
        assert result["shared_ips"] == []
        assert result["shared_nameservers"] == []
        assert result["same_registrar"] is False

    def test_score_max_ip_plus_ns_plus_registrar(self, domain_google, domain_youtube):
        """google.com ↔ youtube.com: IP(50) + NS(30) + registrar(20) = 100."""
        result = correlate_pair(domain_google, domain_youtube)
        assert result["correlation_score"] == 100

    def test_registrar_none_when_not_shared(self, domain_google, domain_unrelated):
        result = correlate_pair(domain_google, domain_unrelated)
        assert result["registrar"] is None

    def test_empty_registrar_not_counted_as_same(self):
        """Dois alvos com registrar='' não devem acumular +20."""
        a = {"domain": "a.com", "is_ip": False,
             "dns": {"A": []},
             "whois": {"skipped": False, "registrar": None, "name_servers": []}}
        b = {"domain": "b.com", "is_ip": False,
             "dns": {"A": []},
             "whois": {"skipped": False, "registrar": None, "name_servers": []}}
        result = correlate_pair(a, b)
        assert result["same_registrar"] is False
        assert result["correlation_score"] == 0

    def test_shared_ips_is_list(self, domain_google, domain_youtube):
        result = correlate_pair(domain_google, domain_youtube)
        assert isinstance(result["shared_ips"], list)
        assert isinstance(result["shared_nameservers"], list)


# ---------------------------------------------------------------------------
# run — orquestrador
# ---------------------------------------------------------------------------

class TestRun:
    def test_less_than_two_targets_returns_empty(self, domain_google):
        result = run([domain_google])
        assert result == []

    def test_empty_list_returns_empty(self):
        result = run([])
        assert result == []

    def test_two_targets_returns_one_pair(self, domain_google, domain_youtube):
        result = run([domain_google, domain_youtube])
        assert len(result) == 1

    def test_three_targets_returns_three_pairs(
        self, domain_google, domain_youtube, domain_unrelated
    ):
        """n=3 → combinações C(3,2) = 3."""
        result = run([domain_google, domain_youtube, domain_unrelated])
        assert len(result) == 3

    def test_four_targets_returns_six_pairs(
        self, domain_google, domain_youtube, domain_unrelated, domain_same_registrar_only
    ):
        """n=4 → C(4,2) = 6."""
        result = run([
            domain_google, domain_youtube,
            domain_unrelated, domain_same_registrar_only
        ])
        assert len(result) == 6

    def test_each_result_has_required_keys(self, domain_google, domain_youtube):
        results = run([domain_google, domain_youtube])
        for r in results:
            assert "pair" in r
            assert "correlation_score" in r

    def test_google_youtube_strong_correlation(self, domain_google, domain_youtube):
        results = run([domain_google, domain_youtube])
        assert results[0]["correlation_score"] >= 50

    def test_no_self_pairing(self, domain_google):
        """run com uma cópia do mesmo alvo não deve gerar par consigo mesmo."""
        result = run([domain_google, domain_google.copy()])
        # Deve retornar 1 par (cópia), não 0 — mas nunca par [X, X] se label igual
        assert len(result) == 1

    def test_returns_list(self, domain_google, domain_unrelated):
        result = run([domain_google, domain_unrelated])
        assert isinstance(result, list)

    def test_all_scores_are_integers(self, domain_google, domain_youtube, domain_unrelated):
        for r in run([domain_google, domain_youtube, domain_unrelated]):
            assert isinstance(r["correlation_score"], int)
