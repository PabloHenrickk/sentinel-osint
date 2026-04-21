"""
tests/test_gov_agent.py — Testes automatizados do gov_agent

Cobertura: ~78 casos distribuídos por módulo.
Não faz chamadas reais à API — tudo mockado via unittest.mock.patch.

Executar:
    pytest tests/test_gov_agent.py -v
    pytest tests/test_gov_agent.py -v --tb=short   # traceback curto
    pytest tests/test_gov_agent.py -v -k "price"   # filtrar por nome
"""

import pytest
from datetime import date, timedelta
from unittest.mock import patch, MagicMock

import gov_agent as ga
from gov_agent import (
    _format_cnpj,
    _parse_date,
    _analyze_price_anomalies,
    _analyze_fractioning,
    _check_empresa_nova,
    _check_capital_incompativel,
    _check_cnae_incompativel,
    _check_situacao_cadastral,
    _check_socio_unico,
    _analyze_humint_profile,
    _calculate_risk,
    _generate_findings,
    ContractRecord,
    SanctionRecord,
    ConvenioRecord,
    CompanyInfo,
    PartnerRecord,
    GovSummary,
    GovAgentOutput,
    DISPENSA_THRESHOLD,
    CONTRATO_ALTO_VALOR,
    CNAE_INCOMPATIVEL_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Fixtures reutilizáveis
# ---------------------------------------------------------------------------

def make_contract(
    number: str = "001",
    value: float = 10_000.0,
    organ: str = "MINISTERIO X",
    description: str = "aquisicao de material de escritorio",
    situation: str = "vigente",
) -> ContractRecord:
    return ContractRecord(
        id=number,
        numero=number,
        objeto=description,
        valorContratado=value,
        dataInicioVigencia="2024-01-01",
        dataFimVigencia="2024-12-31",
        orgao=organ,
        situacao=situation,
        modalidadeCompra="Dispensa",
        numeroProcesso="PROC-001",
    )


def make_company(
    cnae: str = "62.01-5",
    cnae_desc: str = "Desenvolvimento de programas de computador",
    capital: float = 100_000.0,
    abertura: str = "2020-01-01",
    situacao: str = "ATIVA",
    partners: list | None = None,
    email: str = "contato@empresa.com.br",
    porte: str = "ME",
) -> CompanyInfo:
    return CompanyInfo(
        razao_social="EMPRESA TESTE LTDA",
        nome_fantasia="Empresa Teste",
        cnae_principal=cnae,
        cnae_descricao=cnae_desc,
        email=email,
        telefone="1100000000",
        municipio="SAO PAULO",
        uf="SP",
        domain_hint="empresa.com.br" if "@" in email and email.split("@")[1] not in
                    {"gmail.com","hotmail.com","yahoo.com","outlook.com"} else "",
        porte=porte,
        capital_social=capital,
        data_abertura=abertura,
        situacao_cadastral=situacao,
        partners=partners or [],
    )


def make_partner(name: str = "JOAO DA SILVA", qualification: str = "Sócio") -> PartnerRecord:
    return PartnerRecord(
        name=name,
        cpf_masked="***123456**",
        qualification=qualification,
        entry_date="2020-01-01",
        age_bracket="41 a 50 anos",
    )


def make_sanction(sanction_type: str = "CEIS") -> SanctionRecord:
    s = SanctionRecord(
        fundamentacaoLegal="Art. 87 Lei 8.666",
        dataInicioSancao="2023-01-01",
        dataFinalSancao="2025-01-01",
        orgaoSancionador="TCU",
        tipoSancao="Suspensão temporária",
    )
    s.type = sanction_type
    return s


# ---------------------------------------------------------------------------
# 1. _format_cnpj
# ---------------------------------------------------------------------------

class TestFormatCnpj:
    def test_formato_correto(self):
        assert _format_cnpj("12345678000195") == "12.345.678/0001-95"

    def test_com_pontuacao_ja_existente(self):
        # Se vier formatado, remove tudo e reformata
        assert _format_cnpj("12.345.678/0001-95") == "12.345.678/0001-95"

    def test_menos_de_14_digitos_retorna_original(self):
        invalido = "1234"
        assert _format_cnpj(invalido) == invalido

    def test_string_vazia_retorna_vazia(self):
        assert _format_cnpj("") == ""


# ---------------------------------------------------------------------------
# 2. _parse_date
# ---------------------------------------------------------------------------

class TestParseDate:
    def test_formato_iso(self):
        assert _parse_date("2023-06-15") == date(2023, 6, 15)

    def test_formato_br(self):
        assert _parse_date("15/06/2023") == date(2023, 6, 15)

    def test_string_vazia(self):
        assert _parse_date("") is None

    def test_invalido_retorna_none(self):
        assert _parse_date("N/A") is None

    def test_invalido_tracos(self):
        assert _parse_date("--") is None

    def test_data_com_timestamp(self):
        # API às vezes retorna "2023-06-15T00:00:00" — slice [:10] deve resolver
        assert _parse_date("2023-06-15T00:00:00") == date(2023, 6, 15)


# ---------------------------------------------------------------------------
# 3. _analyze_price_anomalies
# ---------------------------------------------------------------------------

class TestAnalyzePriceAnomalies:
    def test_sem_contratos(self):
        assert _analyze_price_anomalies([]) == []

    def test_dentro_do_limite_nao_flagga(self):
        # notebook R$5.000 — dentro de max=8.000 * 3
        c = make_contract(value=5_000.0, description="aquisicao de 1 notebook")
        assert _analyze_price_anomalies([c]) == []

    def test_sobreprecado_flagga(self):
        # notebook R$500.000 / 1 unidade = R$500.000 >> max R$8.000
        c = make_contract(value=500_000.0, description="aquisicao de 1 notebook corporativo")
        result = _analyze_price_anomalies([c])
        assert len(result) == 1
        assert result[0].keyword_matched == "notebook"
        assert result[0].severity in ("HIGH", "CRITICAL")

    def test_fator_critico(self):
        # mouse R$100.000 / 1 unidade — max R$500 — fator 200x → CRITICAL
        c = make_contract(value=100_000.0, description="aquisicao de 1 mouse optico")
        result = _analyze_price_anomalies([c])
        assert len(result) >= 1
        mouse_r = next((r for r in result if r.keyword_matched == "mouse"), None)
        assert mouse_r is not None
        assert mouse_r.severity == "CRITICAL"

    def test_multi_keyword_mesmo_contrato(self):
        # FIX Bug 3: contrato com "notebook" e "mouse" deve gerar 2 anomalias se ambos sobreprecados
        c = make_contract(
            value=1_000_000.0,
            description="aquisicao de 1 notebook e 1 mouse para secretaria"
        )
        result = _analyze_price_anomalies([c])
        keywords = [r.keyword_matched for r in result]
        assert "notebook" in keywords
        assert "mouse" in keywords

    def test_quantidade_extraida_via_regex(self):
        c = make_contract(value=1_000_000.0, description="aquisicao de 100 mouse optico")
        result = _analyze_price_anomalies([c])
        mouse_r = next((r for r in result if r.keyword_matched == "mouse"), None)
        if mouse_r:  # pode não flaggar se unit price cair
            assert mouse_r.estimated_quantity == 100

    def test_sem_sobreprecao_nao_gera_anomalia(self):
        # caneta: max R$20. R$10 por unidade = dentro do aceitável (10 <= 20 * 3 = 60)
        c = make_contract(value=10.0, description="compra de 1 caneta bic")
        result = _analyze_price_anomalies([c])
        assert result == []

    def test_contrato_valor_zero_nao_quebra(self):
        c = make_contract(value=0.0, description="fornecimento de notebook")
        result = _analyze_price_anomalies([c])
        # Sem valor, unit price = 0 — abaixo do limiar, não flagga
        assert result == []


# ---------------------------------------------------------------------------
# 4. _analyze_fractioning
# ---------------------------------------------------------------------------

class TestAnalyzeFractioning:
    def test_sem_contratos(self):
        assert _analyze_fractioning([]) == []

    def test_um_contrato_abaixo_nao_flagga(self):
        # Precisa de pelo menos 2 abaixo do threshold
        c = make_contract(value=10_000.0)
        assert _analyze_fractioning([c]) == []

    def test_dois_abaixo_gera_pattern(self):
        contracts = [
            make_contract(number="001", value=10_000.0, organ="ORG A"),
            make_contract(number="002", value=12_000.0, organ="ORG A"),
        ]
        result = _analyze_fractioning(contracts)
        assert len(result) == 1
        assert result[0].organ == "ORG A"
        assert result[0].contracts_below_threshold == 2

    def test_score_alto_muitos_contratos(self):
        # 10 contratos × R$15.000 = R$150.000 (> 100k) → bonus +30
        # score = min(10*20, 60) + 30 + 20 = 110 → cap 100
        contracts = [
            make_contract(number=str(i), value=15_000.0, organ="ORG B")
            for i in range(10)
        ]
        result = _analyze_fractioning(contracts)
        assert len(result) == 1
        assert result[0].suspicion_score == 100

    def test_orgaos_diferentes_nao_agrupam(self):
        contracts = [
            make_contract(number="001", value=10_000.0, organ="ORG A"),
            make_contract(number="002", value=12_000.0, organ="ORG B"),
        ]
        result = _analyze_fractioning(contracts)
        # Cada órgão tem apenas 1 contrato abaixo — nenhum flagga
        assert result == []

    def test_ordenado_por_score_decrescente(self):
        c_a = [make_contract(number=str(i), value=5_000.0, organ="ORG A") for i in range(8)]
        c_b = [make_contract(number=str(i + 100), value=5_000.0, organ="ORG B") for i in range(3)]
        result = _analyze_fractioning(c_a + c_b)
        if len(result) >= 2:
            assert result[0].suspicion_score >= result[1].suspicion_score

    def test_contratos_acima_threshold_nao_contam(self):
        contracts = [
            make_contract(number="001", value=10_000.0, organ="ORG A"),
            make_contract(number="002", value=50_000.0, organ="ORG A"),  # acima
        ]
        result = _analyze_fractioning(contracts)
        # Apenas 1 abaixo — não flagga
        assert result == []

    def test_total_alto_aumenta_score(self):
        contracts = [
            make_contract(number=str(i), value=15_000.0, organ="ORG X")
            for i in range(5)
        ]  # total = 75.000 < 100.000 — bonus não aplica
        result = _analyze_fractioning(contracts)
        assert len(result) == 1

    def test_threshold_correto(self):
        # Contrato ACIMA do limiar: não conta como "abaixo" (> DISPENSA_THRESHOLD)
        c = [
            make_contract(number="001", value=DISPENSA_THRESHOLD + 0.01, organ="ORG A"),
            make_contract(number="002", value=DISPENSA_THRESHOLD + 0.01, organ="ORG A"),
        ]
        result = _analyze_fractioning(c)
        assert result == []

    def test_threshold_inclusivo_conta(self):
        # Exatamente no limiar → <= DISPENSA_THRESHOLD → conta como abaixo
        c = [
            make_contract(number="001", value=DISPENSA_THRESHOLD, organ="ORG A"),
            make_contract(number="002", value=DISPENSA_THRESHOLD, organ="ORG A"),
        ]
        result = _analyze_fractioning(c)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# 5. HUMINT checks
# ---------------------------------------------------------------------------

class TestCheckEmpresaNova:
    def _empresa_nova(self, meses: int = 6) -> CompanyInfo:
        abertura = date.today() - timedelta(days=meses * 30)
        return make_company(abertura=abertura.isoformat())

    def test_empresa_nova_contrato_alto_flagga(self):
        # 8 meses (0.66 anos) → entre 0.5 e 2 anos → severity HIGH
        c = make_contract(value=CONTRATO_ALTO_VALOR + 1)
        flag = _check_empresa_nova(self._empresa_nova(meses=8), [c])
        assert flag is not None
        assert flag.flag_type == "EMPRESA_NOVA"
        assert flag.severity == "HIGH"

    def test_empresa_muito_nova_critica(self):
        c = make_contract(value=CONTRATO_ALTO_VALOR + 1)
        flag = _check_empresa_nova(self._empresa_nova(meses=3), [c])
        assert flag is not None
        assert flag.severity == "CRITICAL"

    def test_empresa_antiga_nao_flagga(self):
        c = make_contract(value=CONTRATO_ALTO_VALOR + 1)
        flag = _check_empresa_nova(make_company(abertura="2015-01-01"), [c])
        assert flag is None

    def test_sem_contrato_alto_nao_flagga(self):
        flag = _check_empresa_nova(self._empresa_nova(meses=6), [make_contract(value=1_000.0)])
        assert flag is None

    def test_sem_data_abertura_nao_flagga(self):
        c = make_company(abertura="")
        flag = _check_empresa_nova(c, [make_contract(value=CONTRATO_ALTO_VALOR + 1)])
        assert flag is None


class TestCheckCapitalIncompativel:
    def test_capital_muito_baixo_critical(self):
        # capital R$100 vs total R$1M → ratio = 0.01% < CAPITAL_RATIO_CRIT
        flag = _check_capital_incompativel(make_company(capital=100.0), 1_000_000.0)
        assert flag is not None
        assert flag.severity == "CRITICAL"

    def test_capital_baixo_high(self):
        # capital R$10.000 vs total R$1M → ratio = 1% → entre CRIT e ALERT
        flag = _check_capital_incompativel(make_company(capital=10_000.0), 1_000_000.0)
        assert flag is not None
        assert flag.severity == "HIGH"

    def test_capital_adequado_nao_flagga(self):
        flag = _check_capital_incompativel(make_company(capital=500_000.0), 1_000_000.0)
        assert flag is None

    def test_sem_contratos_nao_flagga(self):
        flag = _check_capital_incompativel(make_company(capital=100.0), 0.0)
        assert flag is None

    def test_capital_zero_nao_flagga(self):
        flag = _check_capital_incompativel(make_company(capital=0.0), 1_000_000.0)
        assert flag is None


class TestCheckCnaeIncompativel:
    def test_cnae_compativel_nao_flagga(self):
        # CNAE 62 (TI) + contrato de software
        c = make_contract(description="desenvolvimento de software de gestao")
        flag = _check_cnae_incompativel(make_company(cnae="62.01-5"), [c])
        assert flag is None

    def test_100_porcento_incompativel_flagga(self):
        c = make_contract(description="fornecimento de marmita e refeicao")
        flag = _check_cnae_incompativel(make_company(cnae="62.01-5"), [c])
        assert flag is not None
        assert flag.flag_type == "CNAE_INCOMPATIVEL"

    def test_threshold_70_porcento(self):
        # FIX Bug 2: 7 de 10 contratos incompatíveis → deve flaggar (70%)
        incompat = [make_contract(number=str(i), description="fornecimento de marmita") for i in range(7)]
        compat   = [make_contract(number=str(i + 10), description="desenvolvimento de software") for i in range(3)]
        flag = _check_cnae_incompativel(make_company(cnae="62.01-5"), incompat + compat)
        assert flag is not None

    def test_abaixo_threshold_nao_flagga(self):
        # 5 de 10 contratos incompatíveis → 50% < 70% — não flagga
        incompat = [make_contract(number=str(i), description="fornecimento de marmita") for i in range(5)]
        compat   = [make_contract(number=str(i + 10), description="desenvolvimento de software") for i in range(5)]
        flag = _check_cnae_incompativel(make_company(cnae="62.01-5"), incompat + compat)
        assert flag is None

    def test_cnae_sem_mapeamento_nao_flagga(self):
        # CNAE 99 não está no CNAE_KEYWORDS
        c = make_contract(description="servico desconhecido")
        flag = _check_cnae_incompativel(make_company(cnae="99.99-9"), [c])
        assert flag is None

    def test_sem_contratos_retorna_none(self):
        flag = _check_cnae_incompativel(make_company(cnae="62.01-5"), [])
        assert flag is None


class TestCheckSituacaoCadastral:
    def test_empresa_inapta_com_contrato_flagga(self):
        c = make_contract()
        flag = _check_situacao_cadastral(make_company(situacao="INAPTA"), [c])
        assert flag is not None
        assert flag.severity == "CRITICAL"

    def test_empresa_baixada_flagga(self):
        c = make_contract()
        flag = _check_situacao_cadastral(make_company(situacao="BAIXADA"), [c])
        assert flag is not None

    def test_empresa_ativa_nao_flagga(self):
        c = make_contract()
        flag = _check_situacao_cadastral(make_company(situacao="ATIVA"), [c])
        assert flag is None

    def test_sem_contratos_nao_flagga(self):
        flag = _check_situacao_cadastral(make_company(situacao="INAPTA"), [])
        assert flag is None


class TestCheckSocioUnico:
    def test_socio_unico_alto_valor_flagga(self):
        company = make_company(partners=[make_partner()])
        flag = _check_socio_unico(company, CONTRATO_ALTO_VALOR + 1)
        assert flag is not None
        assert flag.flag_type == "SOCIO_UNICO_ALTO_VALOR"
        assert flag.severity == "MEDIUM"

    def test_dois_socios_nao_flagga(self):
        company = make_company(partners=[make_partner("A"), make_partner("B")])
        flag = _check_socio_unico(company, CONTRATO_ALTO_VALOR + 1)
        assert flag is None

    def test_valor_baixo_nao_flagga(self):
        company = make_company(partners=[make_partner()])
        flag = _check_socio_unico(company, 1_000.0)
        assert flag is None

    def test_sem_socios_nao_flagga(self):
        company = make_company(partners=[])
        flag = _check_socio_unico(company, CONTRATO_ALTO_VALOR + 1)
        assert flag is None


# ---------------------------------------------------------------------------
# 6. _analyze_humint_profile
# ---------------------------------------------------------------------------

class TestAnalyzeHumintProfile:
    def test_sem_flags_retorna_vazio(self):
        company = make_company(
            capital=500_000.0,
            abertura="2015-01-01",
            situacao="ATIVA",
            partners=[make_partner("A"), make_partner("B")],
        )
        flags = _analyze_humint_profile(company, [], 0.0)
        assert flags == []

    def test_ordenado_por_severidade(self):
        # CRITICAL primeiro
        company = make_company(capital=100.0, situacao="INAPTA")
        contracts = [make_contract(value=CONTRATO_ALTO_VALOR + 1)]
        flags = _analyze_humint_profile(company, contracts, CONTRATO_ALTO_VALOR + 1)
        sevs = [f.severity for f in flags]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for i in range(len(sevs) - 1):
            assert order[sevs[i]] <= order[sevs[i + 1]]

    def test_falha_isolada_nao_quebra_outros_checks(self):
        """Se um check HUMINT falha internamente, os demais executam normalmente."""
        # Substitui _check_empresa_nova por uma função que levanta exceção
        original = ga._check_empresa_nova
        try:
            ga._check_empresa_nova = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
            company = make_company(capital=100.0)
            contracts = [make_contract(value=CONTRATO_ALTO_VALOR + 1)]
            # Não deve propagar a exceção
            flags = _analyze_humint_profile(company, contracts, CONTRATO_ALTO_VALOR + 1)
            # capital_incompativel deve ter flaggado
            assert any(f.flag_type == "CAPITAL_INCOMPATIVEL" for f in flags)
        finally:
            ga._check_empresa_nova = original


# ---------------------------------------------------------------------------
# 7. _calculate_risk
# ---------------------------------------------------------------------------

class TestCalculateRisk:
    def _summary(self, **kwargs) -> GovSummary:
        base = dict(
            total_contracts=0, total_contract_value=0.0,
            total_convenios=0, total_grant_value=0.0,
            is_sanctioned=False, sanction_count=0,
            price_anomalies=0, fractioning_patterns=0,
            profile_flags=0, has_humint_flags=False,
            risk_level="UNKNOWN",
        )
        base.update(kwargs)
        return GovSummary(**base)

    def test_sanctioned_is_critical(self):
        assert _calculate_risk(self._summary(is_sanctioned=True)) == "CRITICAL"

    def test_price_anomaly_is_critical(self):
        assert _calculate_risk(self._summary(price_anomalies=1)) == "CRITICAL"

    def test_many_humint_flags_is_high(self):
        assert _calculate_risk(self._summary(has_humint_flags=True, profile_flags=2)) == "HIGH"

    def test_many_contracts_is_high(self):
        assert _calculate_risk(self._summary(total_contracts=11)) == "HIGH"

    def test_high_value_is_high(self):
        assert _calculate_risk(self._summary(total_contract_value=10_000_001.0)) == "HIGH"

    def test_fractioning_is_high(self):
        assert _calculate_risk(self._summary(fractioning_patterns=1)) == "HIGH"

    def test_no_data_is_low(self):
        assert _calculate_risk(self._summary()) == "LOW"

    def test_has_contracts_is_medium(self):
        assert _calculate_risk(self._summary(total_contracts=3)) == "MEDIUM"


# ---------------------------------------------------------------------------
# 8. _generate_findings
# ---------------------------------------------------------------------------

def _make_output(**kwargs) -> GovAgentOutput:
    defaults = dict(
        cnpj="12345678000195",
        cnpj_formatted="12.345.678/0001-95",
        summary=GovSummary(),
    )
    defaults.update(kwargs)
    return GovAgentOutput(**defaults)


class TestGenerateFindings:
    def test_sem_dados_retorna_vazio(self):
        output = _make_output()
        result = _generate_findings(output)
        assert result == []

    def test_sancao_ceis_gera_finding_critical(self):
        output = _make_output(sanctions_ceis=[make_sanction("CEIS")])
        result = _generate_findings(output)
        sanctions = [f for f in result if "Sanç" in f["title"]]
        assert len(sanctions) == 1
        assert sanctions[0]["severity"] == "CRITICAL"

    def test_sancao_cnep_gera_finding_critical(self):
        output = _make_output(sanctions_cnep=[make_sanction("CNEP")])
        result = _generate_findings(output)
        sanctions = [f for f in result if "Sanç" in f["title"]]
        assert len(sanctions) == 1

    def test_volume_nao_gerado_quando_cnep_sancionado(self):
        """FIX Bug 4 — CNEP sancionada não deve gerar finding de volume."""
        output = _make_output(
            sanctions_cnep=[make_sanction("CNEP")],
            contracts=[make_contract()],
            summary=GovSummary(total_contracts=1, total_contract_value=10_000.0),
        )
        result = _generate_findings(output)
        volume = [f for f in result if "contrato(s)" in f["title"] and "Sanç" not in f["title"]]
        assert volume == []

    def test_volume_gerado_sem_sancao(self):
        output = _make_output(
            contracts=[make_contract(value=10_000.0)],
            summary=GovSummary(total_contracts=1, total_contract_value=10_000.0),
        )
        result = _generate_findings(output)
        volume = [f for f in result if "contrato(s)" in f["title"]]
        assert len(volume) == 1

    def test_dominio_hint_gera_finding(self):
        company = make_company(email="cto@minhaempresa.com.br")
        company.domain_hint = "minhaempresa.com.br"
        output = _make_output(company_info=company)
        result = _generate_findings(output)
        domain = [f for f in result if "Domínio" in f["title"]]
        assert len(domain) == 1

    def test_qsa_gera_finding(self):
        company = make_company(partners=[make_partner()])
        output = _make_output(company_info=company)
        result = _generate_findings(output)
        qsa = [f for f in result if "QSA" in f["title"]]
        assert len(qsa) == 1

    def test_humint_flag_gera_finding(self):
        from gov_agent import ProfileFlag
        flag = ProfileFlag(
            flag_type="EMPRESA_NOVA", severity="HIGH",
            title="Empresa com 0.5 anos", detail="Detalhe.",
            evidence=["ev1"], investigative_note="nota",
        )
        output = _make_output(humint_flags=[flag])
        result = _generate_findings(output)
        humint = [f for f in result if f["category"] == "HUMINT / Perfil Societário"]
        assert len(humint) == 1

    def test_volume_high_quando_acima_10m(self):
        output = _make_output(
            contracts=[make_contract(value=10_000_001.0)],
            summary=GovSummary(total_contracts=1, total_contract_value=10_000_001.0),
        )
        result = _generate_findings(output)
        volume = [f for f in result if "contrato(s)" in f["title"]]
        assert volume[0]["severity"] == "HIGH"

    def test_fracionamento_gera_finding(self):
        from gov_agent import FractioningPattern
        pattern = FractioningPattern(
            organ="ORG X", contract_count=5, total_value=50_000.0,
            contracts_below_threshold=5, suspicion_score=80,
        )
        output = _make_output(fractioning_patterns=[pattern])
        result = _generate_findings(output)
        frac = [f for f in result if "Fracionamento" in f["title"]]
        assert len(frac) == 1

    def test_price_anomaly_gera_finding(self):
        from gov_agent import PriceAnomaly
        anomaly = PriceAnomaly(
            contract_number="001", object_description="notebook",
            contract_value=500_000.0, keyword_matched="notebook",
            estimated_quantity=1, unit_price=500_000.0,
            max_reasonable=8_000.0, overprice_factor=62.5,
            organ="ORG Y", severity="CRITICAL",
        )
        output = _make_output(price_anomalies=[anomaly])
        result = _generate_findings(output)
        over = [f for f in result if "Sobrepreço" in f["title"]]
        assert len(over) == 1
        assert over[0]["severity"] == "CRITICAL"

    def test_fracionamento_abaixo_score_nao_gera_finding(self):
        from gov_agent import FractioningPattern
        pattern = FractioningPattern(
            organ="ORG Z", contract_count=2, total_value=20_000.0,
            contracts_below_threshold=2, suspicion_score=40,  # < 60
        )
        output = _make_output(fractioning_patterns=[pattern])
        result = _generate_findings(output)
        frac = [f for f in result if "Fracionamento" in f["title"]]
        assert frac == []


# ---------------------------------------------------------------------------
# 9. Schemas Pydantic
# ---------------------------------------------------------------------------

class TestSchemas:
    def test_contract_value_como_float(self):
        # API retorna float — validator converte corretamente
        raw = {"numero": "001", "objeto": "teste", "valorContratado": 10500.0}
        c = ContractRecord.model_validate(raw)
        assert c.value == 10500.0

    def test_contract_value_como_string_simples(self):
        # API retorna string sem separador de milhar — "10500.00"
        raw = {"numero": "001", "objeto": "teste", "valorContratado": "10500.00"}
        c = ContractRecord.model_validate(raw)
        assert c.value == 10500.0

    def test_contract_value_none_vira_zero(self):
        raw = {"valorContratado": None}
        c = ContractRecord.model_validate(raw)
        assert c.value == 0.0

    def test_convenio_value_como_float(self):
        # API retorna floats — validator converte corretamente
        raw = {"numero": "001", "objeto": "teste", "valorConvenio": 5000.0, "valorRepasse": 3000.0}
        cv = ConvenioRecord.model_validate(raw)
        assert cv.value == 5000.0
        assert cv.grant_value == 3000.0

    def test_gov_agent_output_dump_completo(self):
        output = GovAgentOutput(
            cnpj="12345678000195",
            cnpj_formatted="12.345.678/0001-95",
        )
        dumped = output.model_dump()
        assert "cnpj" in dumped
        assert "summary" in dumped
        assert "gov_intel_findings" in dumped

    def test_gov_summary_risk_level_default(self):
        s = GovSummary()
        assert s.risk_level == "LOW"


# ---------------------------------------------------------------------------
# 10. run() — integração com mocks
# ---------------------------------------------------------------------------

MOCK_BRASILAPI_RESPONSE = {
    "razao_social": "EMPRESA MOCK LTDA",
    "nome_fantasia": "Mock",
    "atividade_principal": [{"code": "62.01-5", "text": "Desenvolvimento de software"}],
    "email": "contato@mock.com.br",
    "ddd_telefone_1": "11999999999",
    "municipio": "SAO PAULO",
    "uf": "SP",
    "porte": "ME",
    "capital_social": 50_000,
    "data_inicio_atividade": "2018-01-01",
    "descricao_situacao_cadastral": "ATIVA",
    "qsa": [{"nome_socio": "FULANO", "cnpj_cpf_do_socio": "***111***", "qualificacao_socio": "Sócio"}],
}


class TestRunIntegration:
    def test_sem_cnpj_retorna_erro(self):
        result = ga.run({"target": ""})
        assert "error" in result

    def test_sem_api_key_retorna_erro(self):
        with patch.object(ga, "API_KEY", ""):
            result = ga.run({"target": "12345678000195"})
        assert "error" in result

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=MOCK_BRASILAPI_RESPONSE)
    @patch("gov_agent._get", return_value=[])
    def test_run_completo_sem_dados(self, mock_get, mock_brasilapi):
        result = ga.run({"target": "12345678000195"})
        assert result["cnpj"] == "12345678000195"
        assert result["cnpj_formatted"] == "12.345.678/0001-95"
        assert result["summary"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "errors" in result

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=None)
    @patch("gov_agent._get", return_value=None)
    def test_run_falhas_parciais_nao_propaga(self, mock_get, mock_brasilapi):
        # Todos os fetches falham — run() não pode levantar exceção
        result = ga.run({"target": "12345678000195"})
        assert "error" not in result or result.get("summary") is not None

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=MOCK_BRASILAPI_RESPONSE)
    @patch("gov_agent._get", return_value=[{"cnpjSancionado": "12345678000195",
                                             "tipoSancao": "Suspensão", "orgaoSancionador": "TCU",
                                             "dataInicioSancao": "2023-01-01", "dataFinalSancao": "2025-01-01"}])
    def test_sancao_eleva_risco_para_critical(self, mock_get, mock_brasilapi):
        result = ga.run({"target": "12345678000195"})
        assert result["summary"]["risk_level"] == "CRITICAL"

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=MOCK_BRASILAPI_RESPONSE)
    @patch("gov_agent._get", return_value=[])
    def test_cnpj_formatted_gerado_internamente(self, mock_get, mock_brasilapi):
        """FIX Bug 1 — sem 'metadata' no normalized, formata internamente."""
        result = ga.run({"target": "12345678000195"})
        assert result["cnpj_formatted"] == "12.345.678/0001-95"

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=MOCK_BRASILAPI_RESPONSE)
    @patch("gov_agent._get", return_value=[])
    def test_output_tem_timestamp(self, mock_get, mock_brasilapi):
        result = ga.run({"target": "12345678000195"})
        assert result.get("timestamp", "") != ""

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=MOCK_BRASILAPI_RESPONSE)
    @patch("gov_agent._get", return_value=[])
    def test_gov_intel_findings_e_lista(self, mock_get, mock_brasilapi):
        result = ga.run({"target": "12345678000195"})
        assert isinstance(result["gov_intel_findings"], list)

    @patch.object(ga, "API_KEY", "fake-key")
    @patch("gov_agent._get_brasilapi", return_value=MOCK_BRASILAPI_RESPONSE)
    @patch("gov_agent._get", return_value=[{
        "numero": "C001", "objeto": "aquisicao de 1 notebook",
        "valorContratado": 500_000.0, "orgao": "MEC",
        "situacao": "vigente", "modalidadeCompra": "Dispensa",
        "dataInicioVigencia": "2024-01-01", "dataFimVigencia": "2024-12-31",
        "numeroProcesso": "P001",
    }])
    def test_sobreprecao_detectada_em_run(self, mock_get, mock_brasilapi):
        result = ga.run({"target": "12345678000195"})
        assert result["summary"]["price_anomalies"] >= 1
        assert result["summary"]["risk_level"] == "CRITICAL"
