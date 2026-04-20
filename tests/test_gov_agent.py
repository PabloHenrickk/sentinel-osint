"""
tests/test_gov_agent.py — Suite completa do gov_agent incluindo camada HUMINT.

Cobre:
  - Deteccao de sobreprecao (varios niveis de severidade)
  - Deteccao de fracionamento (agrupamento por orgao, scoring)
  - HUMINT: empresa nova, capital incompativel, CNAE incompativel,
            situacao inapta, socio unico
  - Calculo de risco composito
  - Parse de QSA (socios)
  - Geracao de findings (presenca e campos obrigatorios)
  - Integracao do run() com API mockada
"""

import sys
import os
import types
from datetime import date, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agents'))

# Mock dotenv antes do import do modulo
dotenv_mock = types.ModuleType("dotenv")
dotenv_mock.load_dotenv = lambda: None
sys.modules["dotenv"] = dotenv_mock

os.environ["TRANSPARENCIA_API_KEY"] = "test_key_fake"

import importlib
import gov_agent
importlib.reload(gov_agent)

from gov_agent import (
    ContractRecord, SanctionRecord, ConvenioRecord,
    CompanyInfo, PartnerRecord, ProfileFlag, GovSummary, GovAgentOutput,
    _analyze_price_anomalies, _analyze_fractioning,
    _check_empresa_nova, _check_capital_incompativel,
    _check_cnae_incompativel, _check_situacao_cadastral,
    _check_socio_unico, _analyze_humint_profile,
    _parse_partners, _calculate_risk, _generate_findings,
    DISPENSA_THRESHOLD, CONTRATO_ALTO_VALOR,
)

passed = 0
failed = 0

def ok(msg: str):
    global passed
    passed += 1
    print(f"  [OK] {msg}")

def fail(msg: str, exc: Exception):
    global failed
    failed += 1
    print(f"  [FAIL] {msg} — {exc}")

def section(title: str):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# Helpers — fabrica contratos com defaults seguros
def make_contract(
    numero="CT-001", objeto="Servico generico", valor=10000.0,
    orgao="Ministerio Teste", situacao="Vigente", modalidade="Pregao"
) -> ContractRecord:
    return ContractRecord.model_validate({
        "id": numero, "numero": numero, "objeto": objeto,
        "valorContratado": valor, "orgao": orgao, "situacao": situacao,
        "dataInicioVigencia": "2024-01-01", "dataFimVigencia": "2024-12-31",
        "modalidadeCompra": modalidade, "numeroProcesso": f"{numero}/2024",
    })

def make_company(
    cnae="62.01-5", cnae_desc="Desenvolvimento de software",
    capital=100000.0, abertura="2020-01-01", situacao="ATIVA",
    porte="ME", email="contato@empresa.com.br", partners=None
) -> CompanyInfo:
    return CompanyInfo(
        razao_social="Empresa Teste Ltda",
        cnae_principal=cnae, cnae_descricao=cnae_desc,
        capital_social=capital, data_abertura=abertura,
        situacao_cadastral=situacao, porte=porte, email=email,
        domain_hint="empresa.com.br" if email else "",
        partners=partners or [],
    )


# ── 1. Sobreprecao ────────────────────────────────────────────────────────

section("1. ANALISE DE SOBREPRECAO")

try:
    c = make_contract(objeto="Aquisicao de 10 mouses opticos USB", valor=30000.0)
    a = _analyze_price_anomalies([c])
    assert len(a) == 1
    assert a[0].keyword_matched == "mouse"
    assert a[0].estimated_quantity == 10
    assert a[0].unit_price == 3000.0
    assert a[0].overprice_factor == 6.0
    assert a[0].severity == "HIGH"
    ok(f"Mouse HIGH: R$3.000/unit, fator {a[0].overprice_factor}x")
except AssertionError as e:
    fail("Mouse HIGH", e)

try:
    c = make_contract(objeto="Compra de 10 canetas esferograficas", valor=50000.0)
    a = _analyze_price_anomalies([c])
    assert len(a) == 1
    assert a[0].severity == "CRITICAL"
    assert a[0].overprice_factor >= 10
    ok(f"Caneta CRITICAL: R${a[0].unit_price:,.2f}/unit, {a[0].overprice_factor:.0f}x")
except AssertionError as e:
    fail("Caneta CRITICAL", e)

try:
    c = make_contract(objeto="Aquisicao de 50 mouses para laboratorio", valor=10000.0)
    a = _analyze_price_anomalies([c])
    assert len(a) == 0
    ok("Preco normal (R$200/mouse) — sem anomalia")
except AssertionError as e:
    fail("Preco normal sem anomalia", e)

try:
    c = make_contract(objeto="Servico de consultoria estrategica", valor=500000.0)
    a = _analyze_price_anomalies([c])
    assert len(a) == 0
    ok("Contrato sem keyword — sem anomalia")
except AssertionError as e:
    fail("Sem keyword sem anomalia", e)

try:
    # Sem quantidade no objeto: usa qty=1, preco unitario = valor total
    c = make_contract(objeto="Aquisicao de notebook para diretoria", valor=100000.0)
    a = _analyze_price_anomalies([c])
    # 100k / 1 = R$100k/notebook > 3x maximo (R$8k) -> HIGH
    assert len(a) == 1
    assert a[0].estimated_quantity == 1
    ok(f"Notebook sem quantidade: qty=1 implicito, unit=R${a[0].unit_price:,.2f}")
except AssertionError as e:
    fail("Notebook sem quantidade", e)


# ── 2. Fracionamento ──────────────────────────────────────────────────────

section("2. DETECCAO DE FRACIONAMENTO")

try:
    contracts = [
        make_contract(f"CT-F0{i}", "Servico TI lote", 17500.0, "Receita Federal")
        for i in range(4)
    ]
    p = _analyze_fractioning(contracts)
    assert len(p) == 1
    assert p[0].contracts_below_threshold == 4
    assert abs(p[0].total_value - 70000.0) < 0.01
    ok(f"4 contratos abaixo de R${DISPENSA_THRESHOLD:,.0f}, total R${p[0].total_value:,.2f}, score={p[0].suspicion_score}")
except AssertionError as e:
    fail("Fracionamento basico", e)

try:
    # Orgaos diferentes — nao devem ser agrupados
    c1 = make_contract("A1", "Servico A", 17000.0, "Orgao A")
    c2 = make_contract("B1", "Servico B", 17000.0, "Orgao B")
    p  = _analyze_fractioning([c1, c2])
    assert len(p) == 0
    ok("Orgaos diferentes nao ativam fracionamento (1 contrato cada)")
except AssertionError as e:
    fail("Orgaos diferentes", e)

try:
    # Apenas 1 contrato abaixo — nao ativa (minimo 2)
    c = make_contract("X1", "Servico X", 17000.0, "Orgao X")
    p = _analyze_fractioning([c])
    assert len(p) == 0
    ok("1 contrato abaixo do limiar — sem fracionamento (minimo 2)")
except AssertionError as e:
    fail("1 contrato minimo", e)

try:
    # Score alto: 4 contratos + total > R$100k
    contracts = [
        make_contract(f"CT-S{i}", "Servico TI", 17500.0, "TCU")
        for i in range(4)
    ]
    # Adiciona contrato grande do mesmo orgao para elevar o total
    contracts.append(make_contract("CT-BIG", "Contrato principal", 200000.0, "TCU"))
    p = _analyze_fractioning(contracts)
    assert len(p) == 1
    assert p[0].suspicion_score >= 80
    ok(f"Score alto com total > R$100k: score={p[0].suspicion_score}/100")
except AssertionError as e:
    fail("Score alto fracionamento", e)


# ── 3. HUMINT — empresa nova ──────────────────────────────────────────────

section("3. HUMINT — EMPRESA NOVA")

try:
    # Empresa aberta ha 3 meses — CRITICAL
    abertura_recente = (date.today() - timedelta(days=90)).isoformat()
    company = make_company(abertura=abertura_recente)
    contracts = [make_contract("CT-BIG", "Contrato grande", 2_000_000.0)]
    flag = _check_empresa_nova(company, contracts)
    assert flag is not None
    assert flag.flag_type == "EMPRESA_NOVA"
    assert flag.severity == "CRITICAL"
    ok(f"Empresa 3 meses + R$2M -> CRITICAL")
except AssertionError as e:
    fail("Empresa nova CRITICAL", e)

try:
    # Empresa aberta ha 18 meses — HIGH
    abertura_1ano = (date.today() - timedelta(days=540)).isoformat()
    company = make_company(abertura=abertura_1ano)
    contracts = [make_contract("CT-MED", "Contrato medio", 1_000_000.0)]
    flag = _check_empresa_nova(company, contracts)
    assert flag is not None
    assert flag.severity == "HIGH"
    ok("Empresa 18 meses + R$1M -> HIGH")
except AssertionError as e:
    fail("Empresa nova HIGH", e)

try:
    # Empresa antiga (5 anos) — nao deve flaggar
    abertura_antiga = (date.today() - timedelta(days=1825)).isoformat()
    company  = make_company(abertura=abertura_antiga)
    contracts = [make_contract("CT-OK", "Contrato ok", 5_000_000.0)]
    flag = _check_empresa_nova(company, contracts)
    assert flag is None
    ok("Empresa 5 anos — sem flag (esperado)")
except AssertionError as e:
    fail("Empresa antiga sem flag", e)

try:
    # Empresa nova mas contratos pequenos — nao deve flaggar
    abertura_recente = (date.today() - timedelta(days=180)).isoformat()
    company = make_company(abertura=abertura_recente)
    contracts = [make_contract("CT-SMALL", "Contrato pequeno", 10_000.0)]
    flag = _check_empresa_nova(company, contracts)
    assert flag is None
    ok(f"Empresa nova + contrato pequeno (< R${CONTRATO_ALTO_VALOR:,.0f}) — sem flag")
except AssertionError as e:
    fail("Empresa nova contrato pequeno", e)


# ── 4. HUMINT — capital incompativel ─────────────────────────────────────

section("4. HUMINT — CAPITAL INCOMPATIVEL")

try:
    company = make_company(capital=1000.0)
    flag    = _check_capital_incompativel(company, 5_000_000.0)
    assert flag is not None
    assert flag.flag_type == "CAPITAL_INCOMPATIVEL"
    assert flag.severity == "CRITICAL"
    ratio   = 1000 / 5_000_000
    ok(f"Capital R$1k vs R$5M -> CRITICAL (razao {ratio*100:.4f}%)")
except AssertionError as e:
    fail("Capital CRITICAL", e)

try:
    company = make_company(capital=20_000.0)
    flag    = _check_capital_incompativel(company, 1_000_000.0)
    assert flag is not None
    assert flag.severity == "HIGH"
    ok(f"Capital R$20k vs R$1M -> HIGH (razao 2%)")
except AssertionError as e:
    fail("Capital HIGH", e)

try:
    # Capital adequado — sem flag
    company = make_company(capital=200_000.0)
    flag    = _check_capital_incompativel(company, 1_000_000.0)
    assert flag is None
    ok("Capital R$200k vs R$1M (20%) — sem flag (adequado)")
except AssertionError as e:
    fail("Capital adequado sem flag", e)

try:
    # Capital zero — sem flag (sem dados suficientes)
    company = make_company(capital=0.0)
    flag    = _check_capital_incompativel(company, 1_000_000.0)
    assert flag is None
    ok("Capital zero (dado ausente) — sem flag")
except AssertionError as e:
    fail("Capital zero sem flag", e)


# ── 5. HUMINT — CNAE incompativel ────────────────────────────────────────

section("5. HUMINT — CNAE INCOMPATIVEL")

try:
    # Empresa de alimentacao ganhando contrato de TI
    company = make_company(cnae="56.11-2", cnae_desc="Restaurantes e similares")
    contracts = [make_contract("CT-TI", "Desenvolvimento de sistema informatizado", 300_000.0)]
    flag = _check_cnae_incompativel(company, contracts)
    assert flag is not None
    assert flag.flag_type == "CNAE_INCOMPATIVEL"
    assert flag.severity == "HIGH"
    ok("Restaurante + contrato TI -> CNAE_INCOMPATIVEL HIGH")
except AssertionError as e:
    fail("CNAE incompativel basico", e)

try:
    # Empresa de TI com contrato de TI — compativel
    company   = make_company(cnae="62.01-5", cnae_desc="Desenvolvimento de software")
    contracts = [make_contract("CT-TI", "Desenvolvimento de sistema de gestao", 500_000.0)]
    flag      = _check_cnae_incompativel(company, contracts)
    assert flag is None
    ok("TI + contrato TI — sem flag (CNAE compativel)")
except AssertionError as e:
    fail("CNAE compativel sem flag", e)

try:
    # CNAE nao mapeado — sem base de comparacao, nao deve flaggar
    company   = make_company(cnae="99.99-9", cnae_desc="Atividade nao mapeada")
    contracts = [make_contract("CT-X", "Contrato qualquer", 100_000.0)]
    flag      = _check_cnae_incompativel(company, contracts)
    assert flag is None
    ok("CNAE nao mapeado — sem flag (sem base de comparacao)")
except AssertionError as e:
    fail("CNAE nao mapeado", e)


# ── 6. HUMINT — situacao cadastral ────────────────────────────────────────

section("6. HUMINT — SITUACAO CADASTRAL")

try:
    company   = make_company(situacao="INAPTA")
    contracts = [make_contract("CT-1", "Contrato ativo", 200_000.0, situacao="Vigente")]
    flag      = _check_situacao_cadastral(company, contracts)
    assert flag is not None
    assert flag.flag_type == "SITUACAO_INAPTA"
    assert flag.severity == "CRITICAL"
    ok("Empresa INAPTA com contrato vigente -> CRITICAL")
except AssertionError as e:
    fail("Situacao INAPTA", e)

try:
    company   = make_company(situacao="ATIVA")
    contracts = [make_contract("CT-1", "Contrato ok", 200_000.0)]
    flag      = _check_situacao_cadastral(company, contracts)
    assert flag is None
    ok("Empresa ATIVA — sem flag")
except AssertionError as e:
    fail("Empresa ATIVA sem flag", e)


# ── 7. HUMINT — socio unico ────────────────────────────────────────────────

section("7. HUMINT — SOCIO UNICO")

try:
    socio   = PartnerRecord(name="Joao da Silva", qualification="Socio-Administrador",
                            entry_date="2023-01-01", age_bracket="31 a 40 anos")
    company = make_company(partners=[socio])
    flag    = _check_socio_unico(company, 2_000_000.0)
    assert flag is not None
    assert flag.flag_type == "SOCIO_UNICO_ALTO_VALOR"
    assert flag.severity == "MEDIUM"
    assert "Joao da Silva" in flag.investigative_note
    ok(f"Socio unico + R$2M -> MEDIUM | nota de investigacao inclui nome")
except AssertionError as e:
    fail("Socio unico alto valor", e)

try:
    # 2 socios — nao deve flaggar
    socios  = [
        PartnerRecord(name="Socio A", qualification="Socio"),
        PartnerRecord(name="Socio B", qualification="Socio"),
    ]
    company = make_company(partners=socios)
    flag    = _check_socio_unico(company, 2_000_000.0)
    assert flag is None
    ok("2 socios — sem flag de socio unico")
except AssertionError as e:
    fail("2 socios sem flag", e)


# ── 8. Parse de QSA ───────────────────────────────────────────────────────

section("8. PARSE DE QSA")

try:
    raw_qsa = [
        {
            "nome_socio": "Maria Aparecida Santos",
            "cnpj_cpf_do_socio": "***123456**",
            "qualificacao_socio": "Socio-Administrador",
            "data_entrada_sociedade": "2022-03-15",
            "faixa_etaria": "41 a 50 anos",
            "nome_representante_legal": "",
        },
        {
            "nome_socio": "Pedro Alves Lima",
            "cnpj_cpf_do_socio": "***789012**",
            "qualificacao_socio": "Socio Ostensivo",
            "data_entrada_sociedade": "2023-07-01",
            "faixa_etaria": "31 a 40 anos",
            "nome_representante_legal": None,
        },
    ]
    partners = _parse_partners(raw_qsa)
    assert len(partners) == 2
    assert partners[0].name == "Maria Aparecida Santos"
    assert partners[0].cpf_masked == "***123456**"
    assert partners[0].qualification == "Socio-Administrador"
    assert partners[0].entry_date == "2022-03-15"
    assert partners[1].name == "Pedro Alves Lima"
    ok(f"QSA parseado: {len(partners)} socios | {partners[0].name} | {partners[1].name}")
except AssertionError as e:
    fail("Parse QSA", e)

try:
    # QSA vazio — lista vazia, sem excecao
    partners = _parse_partners([])
    assert partners == []
    ok("QSA vazio -> lista vazia (sem excecao)")
except AssertionError as e:
    fail("QSA vazio", e)

try:
    # Entrada malformada — ignorada graciosamente
    raw_qsa_bad = [{"nome_socio": "OK"}, None, {"invalido": True}]
    partners = _parse_partners(raw_qsa_bad)
    assert len(partners) >= 1   # pelo menos o primeiro valido
    ok(f"QSA com entrada invalida ignorada: {len(partners)} socio(s) valido(s)")
except AssertionError as e:
    fail("QSA entrada invalida", e)


# ── 9. Calculo de risco composito ─────────────────────────────────────────

section("9. CALCULO DE RISCO COMPOSITO")

risk_cases = [
    (GovSummary(total_contracts=0, is_sanctioned=False, price_anomalies=0), "LOW",
     "sem contratos, sem sancoes"),
    (GovSummary(total_contracts=2, total_contract_value=50_000, is_sanctioned=False,
                price_anomalies=0, profile_flags=0), "MEDIUM", "contratos ativos, sem flags"),
    (GovSummary(total_contracts=15, total_contract_value=5_000_000, is_sanctioned=False,
                price_anomalies=0), "HIGH", ">10 contratos"),
    (GovSummary(is_sanctioned=True, price_anomalies=0), "CRITICAL", "sancao ativa"),
    (GovSummary(is_sanctioned=False, price_anomalies=1), "CRITICAL", "sobreprecao detectado"),
    (GovSummary(is_sanctioned=False, price_anomalies=0, has_humint_flags=True,
                profile_flags=2), "HIGH", "2 flags HUMINT convergentes"),
    (GovSummary(fractioning_patterns=1, total_contracts=3), "HIGH", "fracionamento detectado"),
]

for summary, expected, desc in risk_cases:
    try:
        summary.risk_level = _calculate_risk(summary)
        assert summary.risk_level == expected
        ok(f"Risk {expected}: {desc}")
    except AssertionError as e:
        fail(f"Risk {expected} ({desc})", e)


# ── 10. Geracao de findings ───────────────────────────────────────────────

section("10. GERACAO DE FINDINGS")

try:
    # Finding HUMINT deve ter campos obrigatorios
    flag = ProfileFlag(
        flag_type="EMPRESA_NOVA", severity="HIGH",
        title="Empresa jovem com contrato grande",
        detail="Detalhe do flag",
        evidence=["Evidencia 1"],
        investigative_note="Verificar socios no TSE",
    )
    output = GovAgentOutput(
        cnpj="12345678000100", cnpj_formatted="12.345.678/0001-00",
        company_info=make_company(), humint_flags=[flag],
        summary=GovSummary(total_contracts=0),
    )
    findings = _generate_findings(output)
    humint_findings = [f for f in findings if f["category"] == "HUMINT / Perfil Societario"]
    assert len(humint_findings) >= 1
    hf = humint_findings[0]
    for campo in ("title", "severity", "category", "mitre_id", "description",
                  "evidence", "recommendation", "source", "kill_chain"):
        assert campo in hf, f"Campo '{campo}' ausente"
    assert hf["severity"] == "HIGH"
    ok(f"Finding HUMINT gerado com todos os campos obrigatorios")
except AssertionError as e:
    fail("Finding HUMINT campos obrigatorios", e)

try:
    # Finding de dominio quando domain_hint presente
    company = make_company(email="contato@empresa-xyz.com.br")
    company.domain_hint = "empresa-xyz.com.br"
    output  = GovAgentOutput(
        cnpj="12345678000100", cnpj_formatted="12.345.678/0001-00",
        company_info=company, summary=GovSummary(total_contracts=0),
    )
    findings = _generate_findings(output)
    domain_f = next((f for f in findings if "Dominio" in f["title"]), None)
    assert domain_f is not None
    assert "empresa-xyz.com.br" in str(domain_f["evidence"])
    ok("Finding de dominio gerado: empresa-xyz.com.br")
except AssertionError as e:
    fail("Finding dominio", e)

try:
    # Finding de QSA com socios
    socios = [PartnerRecord(name="Jose Silva", qualification="Socio-Administrador")]
    company = make_company(partners=socios)
    output  = GovAgentOutput(
        cnpj="12345678000100", cnpj_formatted="12.345.678/0001-00",
        company_info=company, summary=GovSummary(total_contracts=0),
    )
    findings = _generate_findings(output)
    qsa_f = next((f for f in findings if "QSA" in f["title"]), None)
    assert qsa_f is not None
    assert "Jose Silva" in str(qsa_f["evidence"])
    assert "tse.jus.br" in qsa_f["recommendation"]
    ok("Finding QSA gerado com nome do socio e referencia TSE")
except AssertionError as e:
    fail("Finding QSA", e)


# ── 11. Integracao run() com mocks ────────────────────────────────────────

section("11. INTEGRACAO run() COM MOCKS")

def _make_mock_response(status: int, data) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = data
    m.text = str(data)
    return m

try:
    normalized = {
        "target": "33000167000101",
        "metadata": {"cnpj_formatted": "33.000.167/0001-01"},
    }

    brasilapi_data = {
        "razao_social": "PETROLEO BRASILEIRO SA",
        "nome_fantasia": "PETROBRAS",
        "atividade_principal": [{"code": "06.10-8", "text": "Extracao de petroleo"}],
        "email": "contato@petrobras.com.br",
        "ddd_telefone_1": "2134345678",
        "municipio": "RIO DE JANEIRO", "uf": "RJ",
        "porte": "DEMAIS", "capital_social": 205_000_000_000.0,
        "data_inicio_atividade": "1953-10-03",
        "descricao_situacao_cadastral": "ATIVA",
        "qsa": [
            {"nome_socio": "UNIAO FEDERAL", "cnpj_cpf_do_socio": "00000000000191",
             "qualificacao_socio": "Socio Administrador",
             "data_entrada_sociedade": "1953-10-03", "faixa_etaria": "N/A"},
        ],
    }

    contratos_data = [
        {"id": "C1", "numero": "CT-PB-001",
         "objeto": "Fornecimento de combustivel para a frota governamental",
         "valorContratado": 50_000_000.0, "orgao": "Ministerio de Minas e Energia",
         "situacao": "Vigente", "dataInicioVigencia": "2024-01-01",
         "dataFimVigencia": "2024-12-31", "modalidadeCompra": "Concorrencia",
         "numeroProcesso": "001/2024"},
    ]

    def mock_get(url, params=None, headers=None, timeout=None):
        if "brasilapi" in url:
            return _make_mock_response(200, brasilapi_data)
        if "/contratos" in url:
            return _make_mock_response(200, contratos_data)
        return _make_mock_response(200, [])

    with patch("requests.get", side_effect=mock_get):
        result = gov_agent.run(normalized)

    assert result["cnpj"] == "33000167000101"
    assert result["company_info"]["razao_social"] == "PETROLEO BRASILEIRO SA"
    assert result["company_info"]["domain_hint"] == "petrobras.com.br"
    assert len(result["company_info"]["partners"]) == 1
    assert result["summary"]["total_contracts"] == 1
    assert result["summary"]["total_contract_value"] == 50_000_000.0
    assert result["summary"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert len(result["gov_intel_findings"]) >= 1
    assert "errors" in result

    ok(f"run() integrado: risk={result['summary']['risk_level']}, "
       f"contracts={result['summary']['total_contracts']}, "
       f"findings={len(result['gov_intel_findings'])}, "
       f"domain={result['company_info']['domain_hint']}")
except Exception as e:
    fail("run() integracao", e)

try:
    # run() sem API key nunca propaga excecao
    import gov_agent as ga
    original = ga.API_KEY
    ga.API_KEY = ""
    result = ga.run({"target": "33000167000101",
                     "metadata": {"cnpj_formatted": "33.000.167/0001-01"}})
    ga.API_KEY = original
    assert "error" in result
    assert result["summary"]["risk_level"] == "UNKNOWN"
    ok("run() sem API key retorna erro estruturado (sem excecao)")
except Exception as e:
    fail("run() sem API key", e)

try:
    # run() com CNPJ vazio nunca propaga excecao
    result = gov_agent.run({"target": "", "metadata": {}})
    assert "error" in result
    ok("run() com CNPJ vazio retorna erro estruturado")
except Exception as e:
    fail("run() CNPJ vazio", e)


# ── Resultado final ───────────────────────────────────────────────────────

print(f"\n{'='*55}")
print(f"  RESULTADO: {passed} passou | {failed} falhou")
print(f"{'='*55}")

if failed > 0:
    sys.exit(1)