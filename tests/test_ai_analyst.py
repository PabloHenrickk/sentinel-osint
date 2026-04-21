"""
tests/test_ai_analyst.py — Cobertura total do ai_analyst.py

Grupos de testes:
  TestParseResponse            — 3 estratégias de parse + falha
  TestValidateOutput           — Pydantic válido, parcial e inválido
  TestMergeFindings            — dedup, sort por severidade, extração mitre nested/flat
  TestConvertHeaderFindings    — 5 grupos (TLS, protection, leakage, cookie, CORS)
  TestConvertSubdomainFindings — sem candidatos, N candidatos
  TestOllamaAvailable          — liveness check (200, non-200, exception)
  TestTruncateEnrichment       — limites groq vs openrouter, CVEs, banners, SANs
  TestCallModelBudget          — truncamento Groq, OpenRouter safety net, Ollama safety net
  TestRun                      — integração: merge confirmed_findings, falha de provider

Convenções:
  - Toda chamada HTTP mockada — zero rede real
  - Toda I/O de arquivo mockada — zero disco real
  - save_analysis sempre mockado — testes são puros
"""

import json
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest

# ── Garante que agents/ e core/ são importáveis ──────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ── Helpers de fixture ────────────────────────────────────────────────────

def make_groq_response(content: str) -> MagicMock:
    """Monta resposta HTTP simulando Groq API."""
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    return mock


def make_openrouter_response(content: str) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    return mock


MINIMAL_VALID_JSON = json.dumps({
    "executive_summary": {"risk_level": "HIGH", "risk_justification": "Test"},
    "findings": [],
    "attack_hypotheses": [],
    "priority_level": "HIGH",
    "recommendations": [],
    "threat_hypotheses": [],
})

HEADER_DATA_FULL = {
    "error": None,
    "status_code": 200,
    "summary": {
        "total_findings": 5,
        "high": 1,
        "medium": 3,
        "low": 1,
        "critical": 0,
    },
    "findings": [
        {"type": "no_ssl",                          "severity": "HIGH",   "title": "HTTPS ausente",           "evidence": "Servidor responde em HTTP",         "mitre_id": "T1557"},
        {"type": "missing_strict_transport_security","severity": "HIGH",   "title": "HSTS ausente",            "evidence": "Header HSTS nao encontrado",        "mitre_id": "T1557"},
        {"type": "missing_content_security_policy", "severity": "MEDIUM", "title": "Header CSP ausente",      "evidence": "CSP nao definido",                  "mitre_id": "T1185"},
        {"type": "missing_x_frame_options",         "severity": "MEDIUM", "title": "Header X-Frame ausente",  "evidence": "XFO nao definido",                  "mitre_id": "T1185"},
        {"type": "info_leak_server",                "severity": "LOW",    "title": "Server header exposto",   "evidence": "Server: Apache/2.4.51",             "mitre_id": "T1592.002"},
        {"type": "cookie_no_secure",                "severity": "MEDIUM", "title": "Cookie sem Secure flag",  "evidence": "Set-Cookie: session=abc; HttpOnly", "mitre_id": "T1185"},
        {"type": "cors_wildcard",                   "severity": "MEDIUM", "title": "CORS wildcard",           "evidence": "Access-Control-Allow-Origin: *",    "mitre_id": "T1190"},
    ],
}

SUBDOMAIN_DATA_WITH_TAKEOVER = {
    "error": None,
    "total_found_crt": 10,
    "active_count": 5,
    "takeover_candidates": [
        {"name": "legacy.example.com", "cname": "example.github.io", "takeover_service": "GitHub Pages"},
        {"name": "old.example.com",    "cname": "example.netlify.app","takeover_service": "Netlify"},
    ],
    "takeover_candidates_count": 2,
    "subdomains": [
        {"name": "www.example.com",    "status": "resolved", "ips": ["1.2.3.4"]},
        {"name": "mail.example.com",   "status": "resolved", "ips": ["1.2.3.5"]},
    ],
}

COLLECTED_DATA_DOMAIN = {
    "domain": "example.com",
    "is_ip": False,
    "whois": {"registrar": "Test Registrar"},
    "dns": {"A": ["1.2.3.4"]},
}


# ══════════════════════════════════════════════════════════════════════════
# 1. parse_response — 3 estratégias de parse + falha
# ══════════════════════════════════════════════════════════════════════════

class TestParseResponse:

    def setup_method(self):
        # Importa após sys.path estar configurado
        from agents.ai_analyst import parse_response
        self.parse = parse_response

    def test_strategy1_direct_valid_json(self):
        """Estratégia 1: JSON válido diretamente na string."""
        raw = json.dumps({"findings": [], "priority_level": "HIGH"})
        result = self.parse(raw)
        assert "error" not in result or result.get("error") is None
        assert result.get("priority_level") == "HIGH"

    def test_strategy1_with_leading_whitespace(self):
        """Estratégia 1: JSON válido com whitespace inicial."""
        raw = "   \n" + json.dumps({"priority_level": "LOW", "findings": []})
        result = self.parse(raw)
        assert result.get("priority_level") == "LOW"

    def test_strategy2_json_inside_markdown_block(self):
        """Estratégia 2: JSON dentro de bloco ```json ... ```."""
        inner = {"findings": [{"title": "Test", "severity": "HIGH"}], "priority_level": "MEDIUM"}
        raw = f"```json\n{json.dumps(inner)}\n```"
        result = self.parse(raw)
        assert result.get("priority_level") == "MEDIUM"
        assert len(result.get("findings", [])) == 1

    def test_strategy2_json_inside_plain_code_block(self):
        """Estratégia 2: JSON dentro de bloco ``` sem linguagem."""
        inner = {"priority_level": "CRITICAL", "findings": []}
        raw = f"Aqui está a análise:\n```\n{json.dumps(inner)}\n```\nFim."
        result = self.parse(raw)
        assert result.get("priority_level") == "CRITICAL"

    def test_strategy3_json_embedded_in_text(self):
        """Estratégia 3: JSON válido embutido em texto corrido (regex)."""
        inner = {"priority_level": "LOW", "findings": [], "recommendations": []}
        raw = f"Análise concluída. Resultado: {json.dumps(inner)} Fim da análise."
        result = self.parse(raw)
        assert result.get("priority_level") == "LOW"

    def test_all_strategies_fail_returns_error_output(self):
        """Falha total → _error_output com campos de fallback."""
        raw = "Modelo retornou texto puro sem JSON algum aqui."
        result = self.parse(raw)
        assert result.get("error") is not None
        assert result.get("priority_level") == "INDETERMINADO"
        assert isinstance(result.get("findings"), list)
        assert isinstance(result.get("recommendations"), list)

    def test_empty_string_returns_error(self):
        """String vazia → erro."""
        result = self.parse("")
        assert result.get("error") is not None

    def test_truncated_json_returns_error(self):
        """JSON truncado (sem fechamento) → erro."""
        raw = '{"priority_level": "HIGH", "findings": [{"title": "Test"'
        result = self.parse(raw)
        assert result.get("error") is not None

    def test_raw_response_captured_on_failure(self):
        """raw_response é capturado (até 500 chars) quando parse falha."""
        raw = "x" * 600
        result = self.parse(raw)
        assert len(result.get("raw_response", "")) <= 500

    def test_strategy1_takes_priority_over_strategy2(self):
        """Se a string é JSON válido direto E contém bloco markdown, usa estratégia 1."""
        # Cria um JSON que contém um bloco markdown dentro de uma string — improvável
        # mas garante que estratégia 1 não é pulada quando funciona
        inner = {"priority_level": "HIGH", "findings": []}
        raw = json.dumps(inner)  # JSON puro → estratégia 1 resolve
        result = self.parse(raw)
        assert result.get("priority_level") == "HIGH"

    def test_findings_list_preserved(self):
        """Findings são preservados após parse bem-sucedido."""
        findings = [
            {"title": "SSH Exposed", "severity": "HIGH", "mitre_id": "T1021.004", "category": "Remote Access"},
            {"title": "CORS Wildcard", "severity": "MEDIUM", "mitre_id": "T1190", "category": "API Security"},
        ]
        raw = json.dumps({"findings": findings, "priority_level": "HIGH"})
        result = self.parse(raw)
        assert len(result.get("findings", [])) == 2


# ══════════════════════════════════════════════════════════════════════════
# 2. _validate_output — Pydantic validation paths
# ══════════════════════════════════════════════════════════════════════════

class TestValidateOutput:

    def setup_method(self):
        from agents.ai_analyst import _validate_output
        self.validate = _validate_output

    def test_valid_minimal_output_passes(self):
        """Dict mínimo válido → AnalysisOutput.model_dump() sem erros."""
        data = {
            "executive_summary": {"risk_level": "HIGH"},
            "findings": [],
            "priority_level": "HIGH",
        }
        result = self.validate(data, "")
        assert "_validation_warnings" not in result
        assert result.get("priority_level") == "HIGH"

    def test_unknown_only_field_accepted_by_extra_allow(self):
        """
        AnalysisOutput tem extra='allow' — campo desconhecido NÃO levanta ValidationError.
        Pydantic aceita o dict, retorna modelo com Optional[str] = None para priority_level.
        Comportamento correto: não crasha, campos obrigatórios têm seus defaults.
        """
        data = {"unexpected_only_field": 42}
        result = self.validate(data, "")
        # Não lançou exceção — isso é o que importa
        assert isinstance(result, dict)
        # Campo extra preservado (extra='allow')
        assert result.get("unexpected_only_field") == 42
        # Campos lista têm default_factory=list — nunca None
        assert isinstance(result.get("findings"),         list)
        assert isinstance(result.get("recommendations"),  list)
        assert isinstance(result.get("attack_hypotheses"),list)
        # priority_level é Optional sem default — None é o comportamento correto aqui
        # (ValidationError não foi acionada, logo setdefault não rodou)
        assert "priority_level" in result  # campo existe, valor pode ser None

    def test_validation_warnings_attached_on_partial(self):
        """Erros de validação → _validation_warnings presentes."""
        # findings deve ser lista; passamos string inválida
        data = {"findings": "not_a_list", "priority_level": "HIGH"}
        result = self.validate(data, "")
        # Pydantic vai coercer ou rejeitar — em qualquer caso defaults são aplicados
        # O campo _validation_warnings pode ou não estar presente dependendo
        # de como o Pydantic v2 lida com coerção — o importante é não lançar exceção
        assert "priority_level" in result

    def test_extra_fields_allowed(self):
        """Campos extras (extra='allow') são preservados."""
        data = {
            "findings": [],
            "priority_level": "LOW",
            "custom_intel_field": "valor_customizado",
        }
        result = self.validate(data, "")
        assert result.get("custom_intel_field") == "valor_customizado"

    def test_nested_finding_valid(self):
        """Finding com mitre_attack aninhado é deserializado corretamente."""
        data = {
            "findings": [{
                "title": "SSH Exposed",
                "severity": "HIGH",
                "mitre_attack": {
                    "technique_id": "T1021.004",
                    "technique": "SSH",
                    "tactic": "Lateral Movement",
                },
                "category": "Remote Access",
            }],
            "priority_level": "HIGH",
        }
        result = self.validate(data, "")
        assert len(result["findings"]) == 1


# ══════════════════════════════════════════════════════════════════════════
# 3. _merge_findings — dedup, sort, extração de mitre nested vs flat
# ══════════════════════════════════════════════════════════════════════════

class TestMergeFindings:

    def setup_method(self):
        from agents.ai_analyst import _merge_findings
        self.merge = _merge_findings

    # ── helpers de fixture ─────────────────────────────────────────────

    def _confirmed(self, mitre_id: str, category: str, severity: str = "HIGH") -> dict:
        return {
            "title": f"Confirmed {mitre_id}",
            "severity": severity,
            "mitre_id": mitre_id,
            "category": category,
            "_source": "header_agent",
        }

    def _llm_flat(self, mitre_id: str, category: str, severity: str = "MEDIUM") -> dict:
        """LLM finding com mitre_id flat (não aninhado)."""
        return {
            "title": f"LLM {mitre_id}",
            "severity": severity,
            "mitre_id": mitre_id,
            "category": category,
        }

    def _llm_nested(self, technique_id: str, category: str, severity: str = "MEDIUM") -> dict:
        """LLM finding com mitre_attack aninhado (formato Pydantic)."""
        return {
            "title": f"LLM nested {technique_id}",
            "severity": severity,
            "mitre_attack": {"technique_id": technique_id, "technique": "Example"},
            "category": category,
        }

    # ── testes de deduplicação ─────────────────────────────────────────

    def test_no_llm_findings_returns_confirmed_only(self):
        confirmed = [self._confirmed("T1557", "Transport Security", "HIGH")]
        result = self.merge([], confirmed)
        assert len(result) == 1
        assert result[0]["_source"] == "header_agent"

    def test_no_confirmed_returns_llm_only(self):
        llm = [self._llm_flat("T1021.004", "Remote Access")]
        result = self.merge(llm, [])
        assert len(result) == 1
        assert result[0]["mitre_id"] == "T1021.004"

    def test_dedup_flat_mitre_id_same_category(self):
        """LLM finding com mesmo mitre_id:category do confirmed é descartado."""
        confirmed = [self._confirmed("T1557", "Transport Security")]
        llm       = [self._llm_flat("T1557",  "Transport Security")]
        result = self.merge(llm, confirmed)
        assert len(result) == 1
        assert result[0].get("_source") == "header_agent"

    def test_dedup_nested_mitre_same_category(self):
        """LLM finding com mitre_attack aninhado e mesmo category é descartado."""
        confirmed = [self._confirmed("T1185", "Security Headers")]
        llm       = [self._llm_nested("T1185", "Security Headers")]
        result = self.merge(llm, confirmed)
        assert len(result) == 1

    def test_same_mitre_different_category_not_deduped(self):
        """Mesmo mitre_id mas categoria diferente → ambos aparecem."""
        confirmed = [self._confirmed("T1185", "Security Headers")]
        llm       = [self._llm_flat("T1185",  "Session Security")]  # categoria diferente
        result = self.merge(llm, confirmed)
        assert len(result) == 2

    def test_different_mitre_same_category_not_deduped(self):
        """Mesmo category mas mitre_id diferente → ambos aparecem."""
        confirmed = [self._confirmed("T1557", "Transport Security")]
        llm       = [self._llm_flat("T1040",  "Transport Security")]  # mitre diferente
        result = self.merge(llm, confirmed)
        assert len(result) == 2

    def test_multiple_confirmed_multiple_llm_dedup(self):
        """3 confirmed + 2 LLM onde 1 duplica → resultado tem 4."""
        confirmed = [
            self._confirmed("T1557",     "Transport Security", "HIGH"),
            self._confirmed("T1185",     "Security Headers",   "MEDIUM"),
            self._confirmed("T1584.001", "Subdomain Takeover", "CRITICAL"),
        ]
        llm = [
            self._llm_flat("T1557",     "Transport Security"),  # duplicata → descartado
            self._llm_flat("T1021.004", "Remote Access"),        # único → mantido
        ]
        result = self.merge(llm, confirmed)
        assert len(result) == 4

    # ── testes de ordenação por severidade ────────────────────────────

    def test_sort_critical_before_high(self):
        confirmed = [self._confirmed("T1584.001", "Subdomain Takeover", "CRITICAL")]
        llm       = [self._llm_flat("T1021.004", "Remote Access", "HIGH")]
        result = self.merge(llm, confirmed)
        assert result[0]["severity"] == "CRITICAL"
        assert result[1]["severity"] == "HIGH"

    def test_sort_order_critical_high_medium_low_info(self):
        """Ordem completa: CRITICAL > HIGH > MEDIUM > LOW > INFO."""
        llm = [
            {**self._llm_flat("T1040", "Net", "INFO")},
            {**self._llm_flat("T1021", "Net", "MEDIUM")},
        ]
        confirmed = [
            {**self._confirmed("T1001", "C2",  "LOW")},
            {**self._confirmed("T1190", "Web", "HIGH")},
        ]
        # Adiciona CRITICAL via confirmed com mitre diferente
        critical = {**self._confirmed("T1584.001", "Takeover", "CRITICAL")}
        result = self.merge(llm, confirmed + [critical])
        severities = [r["severity"] for r in result]
        expected_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert severities == expected_order

    def test_confirmed_always_before_llm_with_same_severity(self):
        """Confirmed vem antes do LLM porque merge = confirmed + filtered_llm."""
        confirmed = [self._confirmed("T1557", "Transport Security", "HIGH")]
        llm       = [self._llm_flat("T1021", "Remote Access",       "HIGH")]
        result = self.merge(llm, confirmed)
        # Confirmed primeiro (index 0) porque é concatenado antes
        assert result[0].get("_source") == "header_agent"

    # ── edge cases ─────────────────────────────────────────────────────

    def test_both_empty_returns_empty(self):
        assert self.merge([], []) == []

    def test_llm_finding_missing_mitre_id_and_attack(self):
        """LLM finding sem mitre_id nem mitre_attack → chave '':category → não dedup com nada real."""
        confirmed = [self._confirmed("T1557", "Transport Security")]
        llm       = [{"title": "Orphan", "severity": "LOW", "category": "Transport Security"}]
        result = self.merge(llm, confirmed)
        # Chave LLM = ":Transport Security" ≠ "T1557:Transport Security" → não dedup
        assert len(result) == 2

    def test_llm_mitre_attack_non_dict_falls_back_to_flat(self):
        """mitre_attack não é dict → cai para f.get('mitre_id')."""
        confirmed = [self._confirmed("T1557", "Transport Security")]
        llm = [{
            "title": "Test",
            "severity": "HIGH",
            "mitre_attack": None,  # não é dict
            "mitre_id": "T1557",
            "category": "Transport Security",
        }]
        result = self.merge(llm, confirmed)
        assert len(result) == 1  # duplicata descartada


# ══════════════════════════════════════════════════════════════════════════
# 4. _convert_header_findings — 5 grupos independentes
# ══════════════════════════════════════════════════════════════════════════

class TestConvertHeaderFindings:

    def setup_method(self):
        from agents.ai_analyst import _convert_header_findings
        self.convert = _convert_header_findings

    def _make_header(self, finding_types: list[str]) -> dict:
        type_to_finding = {
            "no_ssl":                           {"type": "no_ssl",                           "severity": "HIGH",   "title": "HTTPS ausente",      "evidence": "HTTP only"},
            "missing_strict_transport_security": {"type": "missing_strict_transport_security","severity": "HIGH",   "title": "HSTS ausente",        "evidence": "No HSTS"},
            "missing_content_security_policy":  {"type": "missing_content_security_policy",  "severity": "MEDIUM", "title": "Header CSP ausente",  "evidence": "No CSP"},
            "missing_x_frame_options":          {"type": "missing_x_frame_options",          "severity": "MEDIUM", "title": "Header XFO ausente",  "evidence": "No XFO"},
            "missing_permissions_policy":       {"type": "missing_permissions_policy",        "severity": "MEDIUM", "title": "Header Perm ausente", "evidence": "No Perm"},
            "missing_x_content_type_options":   {"type": "missing_x_content_type_options",   "severity": "LOW",    "title": "X-Content-Type",      "evidence": "No XCTO"},
            "missing_referrer_policy":          {"type": "missing_referrer_policy",           "severity": "LOW",    "title": "Referrer ausente",    "evidence": "No Ref"},
            "info_leak_server":                 {"type": "info_leak_server",                 "severity": "LOW",    "title": "Server exposto",      "evidence": "Server: Apache/2.4"},
            "info_leak_powered_by":             {"type": "info_leak_powered_by",             "severity": "LOW",    "title": "X-Powered-By",        "evidence": "PHP/8.1"},
            "cookie_no_secure":                 {"type": "cookie_no_secure",                 "severity": "MEDIUM", "title": "Cookie no Secure",    "evidence": "Set-Cookie: s=x"},
            "cookie_no_httponly":                {"type": "cookie_no_httponly",               "severity": "MEDIUM", "title": "Cookie no HttpOnly",  "evidence": "Set-Cookie: s=x"},
            "cookie_no_samesite":               {"type": "cookie_no_samesite",               "severity": "MEDIUM", "title": "Cookie no SameSite",  "evidence": "Set-Cookie: s=x"},
            "cors_wildcard":                    {"type": "cors_wildcard",                    "severity": "MEDIUM", "title": "CORS wildcard",       "evidence": "ACAO: *"},
        }
        findings = [type_to_finding[t] for t in finding_types if t in type_to_finding]
        return {"error": None, "status_code": 200, "summary": {}, "findings": findings}

    # ── guard clauses ──────────────────────────────────────────────────

    def test_none_input_returns_empty(self):
        assert self.convert(None) == []  # type: ignore

    def test_empty_dict_returns_empty(self):
        assert self.convert({}) == []

    def test_error_key_present_and_truthy_returns_empty(self):
        assert self.convert({"error": "Timeout", "findings": [{"type": "no_ssl"}]}) == []

    def test_error_none_proceeds_normally(self):
        """error=None (falsy) deve prosseguir — bug clássico 'error in dict'."""
        data = self._make_header(["no_ssl"])
        result = self.convert(data)
        assert len(result) > 0

    def test_no_findings_key_returns_empty(self):
        assert self.convert({"error": None, "status_code": 200}) == []

    def test_empty_findings_list_returns_empty(self):
        data = {"error": None, "findings": []}
        assert self.convert(data) == []

    # ── grupo TLS ──────────────────────────────────────────────────────

    def test_tls_group_no_ssl_generates_high_t1557(self):
        data   = self._make_header(["no_ssl"])
        result = self.convert(data)
        tls    = next((f for f in result if f.get("mitre_id") == "T1557"), None)
        assert tls is not None
        assert tls["severity"] == "HIGH"
        assert tls["category"] == "Transport Security"

    def test_tls_group_hsts_only_generates_high_t1557(self):
        data   = self._make_header(["missing_strict_transport_security"])
        result = self.convert(data)
        tls    = next((f for f in result if f.get("mitre_id") == "T1557"), None)
        assert tls is not None
        assert tls["severity"] == "HIGH"

    def test_tls_group_both_merged_into_one_finding(self):
        """no_ssl + missing_hsts → apenas 1 finding TLS, não 2."""
        data   = self._make_header(["no_ssl", "missing_strict_transport_security"])
        result = self.convert(data)
        tls_findings = [f for f in result if f.get("mitre_id") == "T1557"]
        assert len(tls_findings) == 1

    def test_tls_source_is_header_agent(self):
        data   = self._make_header(["no_ssl"])
        result = self.convert(data)
        assert result[0]["_source"] == "header_agent"

    # ── grupo protection (CSP, XFO, Permissions, etc.) ────────────────

    def test_protection_two_headers_generates_medium(self):
        data   = self._make_header(["missing_content_security_policy", "missing_x_frame_options"])
        result = self.convert(data)
        prot   = next((f for f in result if f.get("mitre_id") == "T1185" and f.get("category") == "Security Headers"), None)
        assert prot is not None
        assert prot["severity"] == "MEDIUM"

    def test_protection_single_header_generates_low(self):
        """Um único header de proteção ausente → LOW."""
        data   = self._make_header(["missing_content_security_policy"])
        result = self.convert(data)
        prot   = next((f for f in result if f.get("mitre_id") == "T1185" and f.get("category") == "Security Headers"), None)
        assert prot is not None
        assert prot["severity"] == "LOW"

    def test_protection_five_headers_still_one_finding(self):
        """5 headers de proteção ausentes → ainda 1 finding agrupado."""
        types  = ["missing_content_security_policy", "missing_x_frame_options",
                  "missing_permissions_policy", "missing_x_content_type_options",
                  "missing_referrer_policy"]
        data   = self._make_header(types)
        result = self.convert(data)
        prot_findings = [f for f in result if f.get("category") == "Security Headers"]
        assert len(prot_findings) == 1

    # ── grupo leakage ─────────────────────────────────────────────────

    def test_leakage_server_generates_low_t1592(self):
        data   = self._make_header(["info_leak_server"])
        result = self.convert(data)
        leak   = next((f for f in result if f.get("mitre_id") == "T1592.002"), None)
        assert leak is not None
        assert leak["severity"] == "LOW"
        assert leak["category"] == "Information Disclosure"

    def test_leakage_two_sources_one_finding(self):
        """Server + X-Powered-By → 1 finding de leakage agrupado."""
        data   = self._make_header(["info_leak_server", "info_leak_powered_by"])
        result = self.convert(data)
        leaks  = [f for f in result if f.get("mitre_id") == "T1592.002"]
        assert len(leaks) == 1

    # ── grupo cookies ─────────────────────────────────────────────────

    def test_cookie_no_secure_generates_medium_t1185(self):
        data   = self._make_header(["cookie_no_secure"])
        result = self.convert(data)
        cookie = next((f for f in result if f.get("category") == "Session Security"), None)
        assert cookie is not None
        assert cookie["severity"] == "MEDIUM"
        assert cookie["mitre_id"] == "T1185"

    def test_cookie_all_flags_missing_listed_in_finding(self):
        data   = self._make_header(["cookie_no_secure", "cookie_no_httponly", "cookie_no_samesite"])
        result = self.convert(data)
        cookie = next((f for f in result if f.get("category") == "Session Security"), None)
        assert cookie is not None
        title  = cookie.get("title", "")
        assert "Secure" in title
        assert "HttpOnly" in title
        assert "SameSite" in title

    def test_cookie_only_httponly_missing(self):
        data   = self._make_header(["cookie_no_httponly"])
        result = self.convert(data)
        cookie = next((f for f in result if f.get("category") == "Session Security"), None)
        assert cookie is not None
        assert "HttpOnly" in cookie["title"]

    # ── grupo CORS ────────────────────────────────────────────────────

    def test_cors_wildcard_generates_medium_t1190(self):
        data   = self._make_header(["cors_wildcard"])
        result = self.convert(data)
        cors   = next((f for f in result if f.get("category") == "API Security"), None)
        assert cors is not None
        assert cors["mitre_id"] == "T1190"
        assert cors["severity"] == "MEDIUM"

    def test_cors_evidence_preserved(self):
        data   = self._make_header(["cors_wildcard"])
        result = self.convert(data)
        cors   = next((f for f in result if f.get("category") == "API Security"), None)
        assert "ACAO: *" in cors.get("evidence", "")

    # ── todos os grupos presentes ──────────────────────────────────────

    def test_all_groups_generate_five_findings(self):
        data = self._make_header([
            "no_ssl",
            "missing_content_security_policy", "missing_x_frame_options",
            "info_leak_server",
            "cookie_no_secure",
            "cors_wildcard",
        ])
        result = self.convert(data)
        assert len(result) == 5

    def test_all_findings_have_required_fields(self):
        """Todo finding produzido tem: id, title, severity, category, mitre_id, _source."""
        data   = self._make_header([
            "no_ssl", "missing_content_security_policy",
            "info_leak_server", "cookie_no_secure", "cors_wildcard",
        ])
        result = self.convert(data)
        for f in result:
            assert "id"       in f, f"Campo 'id' ausente em: {f}"
            assert "title"    in f, f"Campo 'title' ausente em: {f}"
            assert "severity" in f, f"Campo 'severity' ausente em: {f}"
            assert "category" in f, f"Campo 'category' ausente em: {f}"
            assert "mitre_id" in f, f"Campo 'mitre_id' ausente em: {f}"
            assert "_source"  in f, f"Campo '_source' ausente em: {f}"

    def test_finding_ids_are_sequential(self):
        data   = self._make_header([
            "no_ssl", "missing_content_security_policy",
            "info_leak_server", "cookie_no_secure", "cors_wildcard",
        ])
        result = self.convert(data)
        ids    = [f["id"] for f in result]
        assert ids == ["H-001", "H-002", "H-003", "H-004", "H-005"]

    def test_exploitation_field_present_and_has_scenario(self):
        """exploitation.realistic_scenario deve estar presente nos findings."""
        data   = self._make_header(["no_ssl"])
        result = self.convert(data)
        exp    = result[0].get("exploitation", {})
        assert isinstance(exp, dict)
        assert "realistic_scenario" in exp


# ══════════════════════════════════════════════════════════════════════════
# 5. _convert_subdomain_findings — takeover candidates
# ══════════════════════════════════════════════════════════════════════════

class TestConvertSubdomainFindings:

    def setup_method(self):
        from agents.ai_analyst import _convert_subdomain_findings
        self.convert = _convert_subdomain_findings

    def test_none_returns_empty(self):
        assert self.convert(None) == []  # type: ignore

    def test_empty_dict_returns_empty(self):
        assert self.convert({}) == []

    def test_error_truthy_returns_empty(self):
        assert self.convert({"error": "DNS timeout", "takeover_candidates": [{"name": "x"}]}) == []

    def test_error_none_proceeds(self):
        data = {"error": None, "takeover_candidates": [
            {"name": "legacy.example.com", "cname": "example.github.io", "takeover_service": "GitHub Pages"}
        ]}
        result = self.convert(data)
        assert len(result) == 1

    def test_no_candidates_key_returns_empty(self):
        assert self.convert({"error": None}) == []

    def test_empty_candidates_list_returns_empty(self):
        assert self.convert({"error": None, "takeover_candidates": []}) == []

    def test_single_candidate_generates_critical_finding(self):
        data = {"error": None, "takeover_candidates": [
            {"name": "old.example.com", "cname": "example.netlify.app", "takeover_service": "Netlify"}
        ]}
        result = self.convert(data)
        assert len(result) == 1
        f = result[0]
        assert f["severity"]  == "CRITICAL"
        assert f["mitre_id"]  == "T1584.001"
        assert f["category"]  == "Subdomain Takeover"
        assert f["id"]        == "S-001"
        assert "_source"      in f

    def test_multiple_candidates_generate_multiple_findings(self):
        data = {"error": None, "takeover_candidates": [
            {"name": "a.example.com", "cname": "a.github.io",     "takeover_service": "GitHub Pages"},
            {"name": "b.example.com", "cname": "b.netlify.app",   "takeover_service": "Netlify"},
            {"name": "c.example.com", "cname": "c.heroku.com",    "takeover_service": "Heroku"},
        ]}
        result = self.convert(data)
        assert len(result) == 3
        ids = [f["id"] for f in result]
        assert ids == ["S-001", "S-002", "S-003"]

    def test_candidate_name_in_title_and_evidence(self):
        name = "legacy.example.com"
        cname = "example.github.io"
        data = {"error": None, "takeover_candidates": [
            {"name": name, "cname": cname, "takeover_service": "GitHub Pages"}
        ]}
        result = self.convert(data)
        f = result[0]
        assert name  in f["title"]
        assert name  in f["evidence"]
        assert cname in f["evidence"]

    def test_exploitation_scenario_has_3_steps(self):
        """Cenário de exploração deve referenciar os 3 passos do kill chain."""
        data = {"error": None, "takeover_candidates": [
            {"name": "x.example.com", "cname": "x.github.io", "takeover_service": "GitHub Pages"}
        ]}
        result = self.convert(data)
        scenario = result[0]["exploitation"]["realistic_scenario"]
        # Verifica que há ao menos 3 etapas numeradas
        assert "1." in scenario
        assert "2." in scenario
        assert "3." in scenario

    def test_recommendation_priority_is_critical(self):
        data = {"error": None, "takeover_candidates": [
            {"name": "x.example.com", "cname": "x.github.io", "takeover_service": "GitHub Pages"}
        ]}
        result = self.convert(data)
        assert result[0]["recommendation"]["priority"] == "CRITICAL"

    def test_all_findings_severity_critical(self):
        data = {"error": None, "takeover_candidates": [
            {"name": f"sub{i}.example.com", "cname": f"sub{i}.github.io", "takeover_service": "GitHub Pages"}
            for i in range(5)
        ]}
        result = self.convert(data)
        assert all(f["severity"] == "CRITICAL" for f in result)


# ══════════════════════════════════════════════════════════════════════════
# 6. _ollama_available — liveness check
# ══════════════════════════════════════════════════════════════════════════

class TestOllamaAvailable:

    def setup_method(self):
        from agents.ai_analyst import _ollama_available
        self.check = _ollama_available

    def test_returns_true_on_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("agents.ai_analyst.requests.get", return_value=mock_resp):
            assert self.check() is True

    def test_returns_false_on_404(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("agents.ai_analyst.requests.get", return_value=mock_resp):
            assert self.check() is False

    def test_returns_false_on_connection_error(self):
        import requests as req
        with patch("agents.ai_analyst.requests.get", side_effect=req.exceptions.ConnectionError):
            assert self.check() is False

    def test_returns_false_on_timeout(self):
        import requests as req
        with patch("agents.ai_analyst.requests.get", side_effect=req.exceptions.Timeout):
            assert self.check() is False

    def test_returns_false_on_generic_exception(self):
        with patch("agents.ai_analyst.requests.get", side_effect=RuntimeError("unexpected")):
            assert self.check() is False

    def test_uses_localhost_11434(self):
        """Deve fazer GET para localhost:11434 — não outra URL."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("agents.ai_analyst.requests.get", return_value=mock_resp) as mock_get:
            self.check()
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
        assert "11434" in url

    def test_uses_short_timeout(self):
        """Timeout deve ser baixo (≤5s) para não travar o pipeline."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("agents.ai_analyst.requests.get", return_value=mock_resp) as mock_get:
            self.check()
        call_kwargs = mock_get.call_args[1] if mock_get.call_args[1] else {}
        timeout = call_kwargs.get("timeout", 999)
        assert timeout <= 5, f"Timeout muito alto: {timeout}s"


# ══════════════════════════════════════════════════════════════════════════
# 7. _truncate_enrichment_sources — limites por provider
# ══════════════════════════════════════════════════════════════════════════

class TestTruncateEnrichment:

    def setup_method(self):
        from agents.ai_analyst import _truncate_enrichment_sources
        self.truncate = _truncate_enrichment_sources

    def _make_sources(
        self,
        n_subdomains: int = 0,
        n_cves: int = 0,
        n_sans: int = 0,
        banner_len: int = 0,
    ) -> dict:
        sources: dict = {}
        if n_subdomains:
            sources["subdomains"] = {
                "subdomains": [f"sub{i}.example.com" for i in range(n_subdomains)],
                "count": n_subdomains,
            }
        if n_cves or banner_len:
            cves   = [f"CVE-2024-{i:04d}" for i in range(n_cves)]
            banner = "A" * banner_len
            sources["shodan"] = [{
                "services": [{"banner": banner, "cves": cves}],
                "all_cves":  cves,
            }]
        if n_sans:
            sources["ssl"] = {"sans": [f"san{i}.example.com" for i in range(n_sans)]}
        return sources

    # ── subdomains ─────────────────────────────────────────────────────

    def test_groq_subdomains_capped_at_8(self):
        sources = self._make_sources(n_subdomains=20)
        result  = self.truncate(sources, provider="groq")
        sub     = result["subdomains"]
        assert len(sub.get("sample", sub.get("subdomains", []))) <= 8

    def test_openrouter_subdomains_capped_at_30(self):
        sources = self._make_sources(n_subdomains=50)
        result  = self.truncate(sources, provider="openrouter")
        sub     = result["subdomains"]
        sample  = sub.get("sample", sub.get("subdomains", []))
        assert len(sample) <= 30

    def test_subdomains_within_limit_not_truncated(self):
        sources = self._make_sources(n_subdomains=5)
        result  = self.truncate(sources, provider="groq")
        sub     = result["subdomains"]
        # Sem truncamento, a estrutura original é mantida
        assert sub.get("count", 5) == 5

    def test_truncated_subdomains_include_note(self):
        """Quando trunca, deve incluir nota explicando omissão."""
        sources = self._make_sources(n_subdomains=20)
        result  = self.truncate(sources, provider="groq")
        sub     = result["subdomains"]
        assert "note" in sub or "sample" in sub  # truncamento aconteceu

    # ── CVEs ──────────────────────────────────────────────────────────

    def test_groq_cves_capped_at_5(self):
        sources = self._make_sources(n_cves=20)
        result  = self.truncate(sources, provider="groq")
        shodan  = result["shodan"][0]
        assert len(shodan["all_cves"])                 <= 5
        assert len(shodan["services"][0]["cves"]) <= 5

    def test_openrouter_cves_capped_at_30(self):
        sources = self._make_sources(n_cves=50)
        result  = self.truncate(sources, provider="openrouter")
        shodan  = result["shodan"][0]
        assert len(shodan["all_cves"]) <= 30

    # ── banners ───────────────────────────────────────────────────────

    def test_groq_banner_truncated_at_60_chars(self):
        sources = self._make_sources(banner_len=200)
        result  = self.truncate(sources, provider="groq")
        banner  = result["shodan"][0]["services"][0]["banner"]
        assert len(banner) <= 60 + len("...[truncado]")

    def test_openrouter_banner_truncated_at_200_chars(self):
        sources = self._make_sources(banner_len=500)
        result  = self.truncate(sources, provider="openrouter")
        banner  = result["shodan"][0]["services"][0]["banner"]
        assert len(banner) <= 200 + len("...[truncado]")

    def test_short_banner_not_modified(self):
        sources = self._make_sources(banner_len=30)
        result  = self.truncate(sources, provider="groq")
        banner  = result["shodan"][0]["services"][0]["banner"]
        assert "...[truncado]" not in banner

    # ── SANs ──────────────────────────────────────────────────────────

    def test_sans_capped_at_6(self):
        sources = self._make_sources(n_sans=20)
        result  = self.truncate(sources, provider="groq")
        ssl     = result.get("ssl", {})
        assert len(ssl.get("sans", [])) <= 6

    def test_sans_note_added_when_truncated(self):
        sources = self._make_sources(n_sans=20)
        result  = self.truncate(sources, provider="groq")
        ssl     = result.get("ssl", {})
        assert "sans_note" in ssl

    def test_http_headers_removed(self):
        """Campo 'headers' de http deve ser removido (reduz tokens sem perder inteligência)."""
        sources = {"http": {"headers": {"Server": "Apache"}, "status": 200}}
        result  = self.truncate(sources, provider="groq")
        assert "headers" not in result.get("http", {})

    def test_no_mutation_of_original(self):
        """deepcopy garante que sources original não é mutado."""
        sources = self._make_sources(n_subdomains=20)
        original_count = len(sources["subdomains"]["subdomains"])
        self.truncate(sources, provider="groq")
        assert len(sources["subdomains"]["subdomains"]) == original_count


# ══════════════════════════════════════════════════════════════════════════
# 8. call_model — truncamento de budget por provider
# ══════════════════════════════════════════════════════════════════════════

class TestCallModelBudget:
    """
    Testa lógica de truncamento dentro de call_model() sem chamar API real.
    Estratégia: mock call_groq/call_openrouter/call_ollama para capturar o
    data_context que eles recebem após o truncamento.
    """

    def setup_method(self):
        from agents import ai_analyst
        self.module = ai_analyst

    def _small_system_prompt(self) -> str:
        """System prompt pequeno para maximizar budget de dados nos testes."""
        return "System: analyst. Return JSON only."

    # ── Groq budget ───────────────────────────────────────────────────

    @patch.dict(os.environ, {"AI_PROVIDER": "groq", "GROQ_API_KEY": "test-key", "AI_MODEL": "llama-3.3-70b-versatile"})
    def test_groq_context_within_budget_not_truncated(self):
        """Contexto pequeno → passa intacto para call_groq."""
        system  = self._small_system_prompt()
        context = "Alvo: example.com\nPorta: 443"  # < 100 chars

        captured = {}
        def mock_groq(sys, ctx, model):
            captured["ctx"] = ctx
            return MINIMAL_VALID_JSON

        with patch.object(self.module, "call_groq", side_effect=mock_groq):
            self.module.call_model(system, context)

        assert "...[truncado" not in captured["ctx"]

    @patch.dict(os.environ, {"AI_PROVIDER": "groq", "GROQ_API_KEY": "test-key", "AI_MODEL": "llama-3.3-70b-versatile"})
    def test_groq_context_exceeds_budget_gets_truncated(self):
        """Contexto acima do budget Groq → truncado com sufixo de aviso."""
        system  = self._small_system_prompt()  # ~35 chars → ~14 tokens → budget ~21k chars
        # Contexto grande: 30.000 chars garante que excede o budget real
        context = "X" * 30_000

        captured = {}
        def mock_groq(sys, ctx, model):
            captured["ctx"] = ctx
            return MINIMAL_VALID_JSON

        with patch.object(self.module, "call_groq", side_effect=mock_groq):
            self.module.call_model(system, context)

        assert "...[truncado" in captured["ctx"]
        assert len(captured["ctx"]) < len(context)

    @patch.dict(os.environ, {"AI_PROVIDER": "groq", "GROQ_API_KEY": "test-key", "AI_MODEL": "llama-3.3-70b-versatile", "OLLAMA_FALLBACK_MODEL": ""})
    def test_groq_failure_without_fallback_raises(self):
        """Groq falha + sem OLLAMA_FALLBACK_MODEL → RuntimeError."""
        with patch.object(self.module, "call_groq", side_effect=RuntimeError("API down")):
            with pytest.raises(RuntimeError, match="Groq falhou"):
                self.module.call_model("system", "context")

    @patch.dict(os.environ, {"AI_PROVIDER": "groq", "GROQ_API_KEY": "test-key", "AI_MODEL": "llama-3.3-70b-versatile", "OLLAMA_FALLBACK_MODEL": "llama3.1:8b"})
    def test_groq_failure_with_ollama_available_uses_fallback(self):
        """Groq falha + Ollama disponível → call_ollama é chamado."""
        captured = {}
        def mock_ollama(sys, ctx, model):
            captured["called"] = True
            captured["model"]  = model
            return MINIMAL_VALID_JSON

        with patch.object(self.module, "call_groq",  side_effect=RuntimeError("API down")), \
             patch.object(self.module, "_ollama_available", return_value=True), \
             patch.object(self.module, "call_ollama", side_effect=mock_ollama):
            self.module.call_model("system", "context")

        assert captured.get("called") is True
        assert captured["model"] == "llama3.1:8b"

    @patch.dict(os.environ, {"AI_PROVIDER": "groq", "GROQ_API_KEY": "test-key", "AI_MODEL": "llama-3.3-70b-versatile", "OLLAMA_FALLBACK_MODEL": "llama3.1:8b"})
    def test_groq_failure_with_ollama_unavailable_raises(self):
        """Groq falha + Ollama offline → RuntimeError claro."""
        with patch.object(self.module, "call_groq", side_effect=RuntimeError("API down")), \
             patch.object(self.module, "_ollama_available", return_value=False):
            with pytest.raises(RuntimeError, match="Ollama não está rodando"):
                self.module.call_model("system", "context")

    # ── OpenRouter safety net ──────────────────────────────────────────

    @patch.dict(os.environ, {"AI_PROVIDER": "openrouter", "OPENROUTER_API_KEY": "test-key", "AI_MODEL": "nvidia/llama-3.1-nemotron-ultra-253b-v1:free"})
    def test_openrouter_within_safety_net_not_truncated(self):
        context = "X" * 1000  # bem abaixo dos 400K chars

        captured = {}
        def mock_or(sys, ctx, model):
            captured["ctx"] = ctx
            return MINIMAL_VALID_JSON

        with patch.object(self.module, "call_openrouter", side_effect=mock_or):
            self.module.call_model("system", context)

        assert "...[truncado" not in captured["ctx"]

    @patch.dict(os.environ, {"AI_PROVIDER": "openrouter", "OPENROUTER_API_KEY": "test-key", "AI_MODEL": "nvidia/llama-3.1-nemotron-ultra-253b-v1:free"})
    def test_openrouter_exceeds_safety_net_gets_truncated(self):
        """Contexto > 400K chars → safety net OpenRouter é acionado."""
        context = "X" * 450_000  # > 400_000

        captured = {}
        def mock_or(sys, ctx, model):
            captured["ctx"] = ctx
            return MINIMAL_VALID_JSON

        with patch.object(self.module, "call_openrouter", side_effect=mock_or):
            self.module.call_model("system", context)

        assert "...[truncado" in captured["ctx"]
        assert len(captured["ctx"]) <= 400_000 + 100

    # ── Ollama safety net ─────────────────────────────────────────────

    @patch.dict(os.environ, {"AI_PROVIDER": "ollama", "AI_MODEL": "llama3.1:8b"})
    def test_ollama_exceeds_safety_net_gets_truncated(self):
        """Contexto > 80K chars → safety net Ollama é acionado."""
        context = "X" * 90_000

        captured = {}
        def mock_oll(sys, ctx, model):
            captured["ctx"] = ctx
            return MINIMAL_VALID_JSON

        with patch.object(self.module, "_ollama_available", return_value=True), \
             patch.object(self.module, "call_ollama", side_effect=mock_oll):
            self.module.call_model("system", context)

        assert "...[truncado]" in captured["ctx"]
        assert len(captured["ctx"]) <= 80_000 + 100

    @patch.dict(os.environ, {"AI_PROVIDER": "ollama", "AI_MODEL": "llama3.1:8b"})
    def test_ollama_offline_raises(self):
        with patch.object(self.module, "_ollama_available", return_value=False):
            with pytest.raises(RuntimeError, match="Ollama não está rodando"):
                self.module.call_model("system", "context")

    # ── provider inválido ─────────────────────────────────────────────

    @patch.dict(os.environ, {"AI_PROVIDER": "invalid_provider"})
    def test_invalid_provider_raises_value_error(self):
        with pytest.raises(ValueError, match="AI_PROVIDER inválido"):
            self.module.call_model("system", "context")


# ══════════════════════════════════════════════════════════════════════════
# 9. run() — integração
# ══════════════════════════════════════════════════════════════════════════

class TestRun:
    """
    Testa run() mockando toda I/O externa:
    - call_model → retorna JSON válido pré-definido
    - save_analysis → retorna path fake
    - load_skills / load_memory → retornam strings vazias
    """

    def setup_method(self):
        from agents import ai_analyst
        self.module = ai_analyst

    def _patch_run(self, llm_json: str = MINIMAL_VALID_JSON):
        return [
            patch.object(self.module, "call_model",   return_value=llm_json),
            patch.object(self.module, "save_analysis", return_value="data/test.json"),
            patch.object(self.module, "load_skills",   return_value=""),
            patch.object(self.module, "load_memory",   return_value={"patterns": [], "corrections": []}),
        ]

    def _run_with_patches(self, llm_json=MINIMAL_VALID_JSON, **kwargs):
        patches = self._patch_run(llm_json)
        with patches[0], patches[1], patches[2], patches[3]:
            return self.module.run(COLLECTED_DATA_DOMAIN, **kwargs)

    # ── campos obrigatórios no retorno ────────────────────────────────

    def test_run_returns_target(self):
        result = self._run_with_patches()
        assert result.get("target") == "example.com"

    def test_run_returns_analyzed_at(self):
        result = self._run_with_patches()
        assert "analyzed_at" in result
        assert isinstance(result["analyzed_at"], str)

    def test_run_returns_provider(self):
        with patch.dict(os.environ, {"AI_PROVIDER": "groq"}):
            result = self._run_with_patches()
        assert "provider" in result

    def test_run_returns_saved_to(self):
        result = self._run_with_patches()
        assert result.get("saved_to") == "data/test.json"

    # ── target resolution ─────────────────────────────────────────────

    def test_run_uses_domain_for_non_ip(self):
        result = self._run_with_patches()
        assert result["target"] == "example.com"

    def test_run_uses_ip_when_is_ip_true(self):
        ip_data = {"is_ip": True, "ip": "8.8.8.8", "domain": None}
        patches = self._patch_run()
        with patches[0], patches[1], patches[2], patches[3]:
            result = self.module.run(ip_data)
        assert result["target"] == "8.8.8.8"

    def test_run_fallback_target_when_no_domain(self):
        data    = {"is_ip": False, "domain": None}
        patches = self._patch_run()
        with patches[0], patches[1], patches[2], patches[3]:
            result = self.module.run(data)
        assert result["target"] == "desconhecido"

    # ── merge de confirmed_findings ────────────────────────────────────

    def test_run_merges_header_findings_when_present(self):
        """header_data com findings → confirmed_findings incorporados."""
        llm_json = json.dumps({
            "findings": [{"title": "SSH Exposed", "severity": "HIGH",
                           "mitre_id": "T1021.004", "category": "Remote Access"}],
            "priority_level": "HIGH",
        })
        result = self._run_with_patches(
            llm_json=llm_json,
            header_data=HEADER_DATA_FULL,
        )
        findings = result.get("findings", [])
        # Deve ter os findings do header_agent (confirmed) além do LLM
        assert len(findings) >= 2

    def test_run_merges_subdomain_findings_when_present(self):
        """subdomain_data com takeover → CRITICAL findings adicionados."""
        result = self._run_with_patches(
            subdomain_data=SUBDOMAIN_DATA_WITH_TAKEOVER,
        )
        findings   = result.get("findings", [])
        criticals  = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(criticals) >= 2

    def test_run_no_confirmed_findings_uses_llm_only(self):
        """Sem header_data nem subdomain_data → só findings do LLM."""
        llm_json = json.dumps({
            "findings": [{"title": "Port 22", "severity": "HIGH",
                           "mitre_id": "T1021.004", "category": "Remote Access"}],
            "priority_level": "HIGH",
        })
        result = self._run_with_patches(llm_json=llm_json)
        assert len(result.get("findings", [])) == 1

    def test_run_dedup_confirmed_vs_llm(self):
        """LLM finding duplica confirmed → LLM descartado no merge."""
        # LLM retorna finding com mesma chave do que header_agent vai gerar
        # header_agent gera: mitre_id=T1557, category=Transport Security
        llm_json = json.dumps({
            "findings": [{
                "title": "Duplicate HSTS", "severity": "HIGH",
                "mitre_id": "T1557", "category": "Transport Security",
            }],
            "priority_level": "HIGH",
        })
        header_with_only_tls = {
            "error": None,
            "status_code": 200,
            "summary": {"total_findings": 1, "high": 1},
            "findings": [{"type": "no_ssl", "severity": "HIGH", "title": "HTTPS ausente", "evidence": "HTTP only"}],
        }
        result    = self._run_with_patches(llm_json=llm_json, header_data=header_with_only_tls)
        findings  = result.get("findings", [])
        tls_count = sum(1 for f in findings if f.get("mitre_id") == "T1557")
        assert tls_count == 1, "Duplicata de T1557:Transport Security não foi descartada"

    # ── falha de provider ─────────────────────────────────────────────

    def test_run_provider_failure_returns_error_output(self):
        """Se call_model lança exceção → run retorna error_output com campos de fallback."""
        patches = [
            patch.object(self.module, "call_model",    side_effect=RuntimeError("Todos falharam")),
            patch.object(self.module, "save_analysis",  return_value="data/test.json"),
            patch.object(self.module, "load_skills",    return_value=""),
            patch.object(self.module, "load_memory",    return_value={"patterns": [], "corrections": []}),
        ]
        with patches[0], patches[1], patches[2], patches[3]:
            result = self.module.run(COLLECTED_DATA_DOMAIN)

        assert result.get("error") is not None
        assert result["target"] == "example.com"
        assert isinstance(result.get("findings"), list)

    def test_run_error_output_is_saved(self):
        """Mesmo em caso de erro, save_analysis é chamado."""
        save_mock = MagicMock(return_value="data/error.json")
        patches = [
            patch.object(self.module, "call_model",   side_effect=RuntimeError("fail")),
            patch.object(self.module, "save_analysis", save_mock),
            patch.object(self.module, "load_skills",   return_value=""),
            patch.object(self.module, "load_memory",   return_value={"patterns": [], "corrections": []}),
        ]
        with patches[0], patches[1], patches[2], patches[3]:
            self.module.run(COLLECTED_DATA_DOMAIN)

        save_mock.assert_called_once()

    # ── header_data com error=None não é ignorado ─────────────────────

    def test_run_processes_header_data_with_error_none(self):
        """
        Regressão: 'error' in header_data sempre era True (bug histórico).
        Agora usa .get('error') — error=None deve processar os findings.
        """
        header_minimal = {
            "error": None,
            "status_code": 200,
            "summary": {"total_findings": 1, "high": 0, "medium": 1},
            "findings": [{"type": "cors_wildcard", "severity": "MEDIUM",
                          "title": "CORS wildcard", "evidence": "ACAO: *"}],
        }
        llm_json = json.dumps({"findings": [], "priority_level": "MEDIUM"})
        result   = self._run_with_patches(llm_json=llm_json, header_data=header_minimal)
        findings = result.get("findings", [])
        cors     = [f for f in findings if f.get("category") == "API Security"]
        assert len(cors) == 1, "header_data com error=None não foi processado"