import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from core.input_resolver import normalize
from core.txt_parser import parse as parse_txt

from core.database import Database

# ── CORES ANSI ──────────────────────────────────────────────
CY  = "\033[96m"
GR  = "\033[92m"
RD  = "\033[91m"
YL  = "\033[93m"
DM  = "\033[2m"
BLD = "\033[1m"
RS  = "\033[0m"

SESSION_DIR = Path("data/sessions")


def _load_agent(name: str):
    try:
        import importlib
        module = importlib.import_module(f"agents.{name}")
        return module.run
    except ImportError as e:
        err_msg = str(e)
        def _agent_unavailable(*args, **kwargs):
            return {"error": f"Agente '{name}' indisponível: {err_msg}"}
        print(f"  {YL}⚠{RS}  Agente '{name}' não carregado: {err_msg}")
        return _agent_unavailable
    except SyntaxError as e:
        err_msg = str(e)
        def _agent_broken(*args, **kwargs):
            return {"error": f"Agente '{name}' com erro de sintaxe: {err_msg}"}
        print(f"  {RD}✖{RS}  Agente '{name}' com erro de sintaxe: {err_msg}")
        return _agent_broken


# ── CHECKPOINT ──────────────────────────────────────────────

def _session_path(targets: list[str]) -> Path:
    key = "_".join(sorted(targets))[:60].replace("/", "-")
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    return SESSION_DIR / f"session_{key}.json"


def load_session(targets: list[str]) -> dict:
    path = _session_path(targets)
    if path.exists():
        try:
            state     = json.loads(path.read_text(encoding="utf-8"))
            completed = state.get("completed", [])
            if completed:
                print(f"  {YL}⚠{RS}  Sessão retomada — {len(completed)} alvo(s) já processado(s)")
            return state
        except Exception:
            pass
    return {"completed": [], "aprovados": [], "targets": targets}


def save_session(state: dict, targets: list[str]) -> None:
    path = _session_path(targets)
    try:
        path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print(f"  {YL}⚠{RS}  Falha ao salvar checkpoint: {e}")


def clear_session(targets: list[str]) -> None:
    path = _session_path(targets)
    if path.exists():
        path.unlink()


# ── UI ──────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    print(f"""
{CY}{BLD}
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{RS}
{DM}  OSINT Intelligence Platform — v1.0.0-dev{RS}
{DM}  ─────────────────────────────────────────────────────────{RS}
""")


def line(char="─", color=DM):
    print(f"{color}{char * 58}{RS}")


def label(text: str, value: str, color=CY):
    print(f"  {DM}{text:<18}{RS}{color}{value}{RS}")


def status_ok(msg: str):   print(f"  {GR}✔{RS}  {msg}")
def status_warn(msg: str): print(f"  {YL}⚠{RS}  {msg}")
def status_err(msg: str):  print(f"  {RD}✖{RS}  {msg}")
def status_info(msg: str): print(f"  {CY}→{RS}  {msg}")


def header_section(title: str):
    print()
    line()
    print(f"  {BLD}{title}{RS}")
    line()


def input_targets() -> list[str]:
    print(f"\n  {CY}ALVOS{RS}")
    print(f"  {DM}Aceita qualquer formato — o sistema detecta e roteia automaticamente.{RS}")
    print(f"  {DM}Exemplos:{RS}")
    print(f"  {DM}  domínio   →  petrobras.com.br{RS}")
    print(f"  {DM}  IP        →  45.33.32.156{RS}")
    print(f"  {DM}  URL       →  https://github.com/PabloHenrickk{RS}")
    print(f"  {DM}  e-mail    →  contato@empresa.com.br{RS}")
    print(f"  {DM}  CNPJ      →  33.000.167/0001-01{RS}")
    print(f"  {DM}  múltiplos →  google.com, 8.8.8.8, 12.345.678/0001-90{RS}\n")
    raw = input(f"  {BLD}>{RS} ").strip()
    if not raw:
        status_err("Nenhum alvo informado.")
        sys.exit(1)
    return [t.strip() for t in raw.split(",") if t.strip()]


def input_options() -> dict:
    """Pergunta opções de análise antes de iniciar o pipeline."""
    print(f"\n  {CY}OPÇÕES{RS}")
    print(f"  {DM}Enumeração de subdomínios via crt.sh (pode ser lento em domínios grandes).{RS}")
    raw = input(f"  Habilitar subdomains? {DM}[s/N]{RS} ").strip().lower()
    enable_subdomains = raw in ("s", "sim", "y", "yes")
    return {"enable_subdomains": enable_subdomains}


def print_infra_result(result: dict):
    if "error" in result and not result.get("open_ports"):
        status_warn(f"Infra: {result['error']}")
        if result.get("provider_errors"):
            for err in result["provider_errors"]:
                print(f"      {DM}✖ {err}{RS}")
        return

    provider = result.get("provider_used", "desconhecido")
    cdn      = result.get("cdn_detected")

    print()
    label("Provider usado",  provider,                         color=DM)
    label("Organização",     result.get("organization", "—"))
    label("País / Cidade",   f"{result.get('country','—')} / {result.get('city','—')}")
    label("ASN",             result.get("asn") or "—",         color=DM)
    label("Sistema Op.",     result.get("os") or "—",          color=DM)
    label("Portas abertas",  str(result.get("open_ports", [])))

    if cdn:
        status_warn(f"CDN detectada: {cdn} — dados refletem a CDN, não o servidor de origem")

    vulns = result.get("vulns", [])
    label("CVEs", ", ".join(vulns) if vulns else "Nenhum indexado",
          color=RD if vulns else DM)

    services = result.get("services", [])
    critical = [s for s in services if s.get("severity") == "CRÍTICO"]
    if critical:
        print()
        status_warn(f"{len(critical)} serviço(s) CRÍTICO(s):")
        for s in critical:
            print(f"      {RD}● Porta {s['port']} — {s['description']}{RS}")
            if s.get("mitre"):
                m = s["mitre"]
                print(f"        {DM}{m['technique_id']} — {m['technique_name']}{RS}")


def print_enrichment_summary(summary: dict):
    subdomain_count = summary.get("subdomain_count", 0)
    cve_count       = summary.get("total_cves", 0)
    vt_flagged      = summary.get("vt_flagged", False)
    abuse_score     = summary.get("max_abuse_score", 0)
    missing_headers = summary.get("missing_security_headers", [])
    tech_stack      = summary.get("tech_stack", [])
    server_banner   = summary.get("server_banner", "")
    ssl_expiring    = summary.get("ssl_expiring_soon", False)
    ssl_expired     = summary.get("ssl_expired", False)
    exposed         = summary.get("exposed_services", [])

    print()
    if subdomain_count:
        status_warn(f"{subdomain_count} subdomínio(s) encontrado(s) via crt.sh")
        for s in summary.get("subdomains", [])[:5]:
            print(f"      {DM}↳ {s}{RS}")

    if cve_count:
        status_err(f"{cve_count} CVE(s) indexado(s) no Shodan")
        for cve in summary.get("cves", [])[:5]:
            print(f"      {RD}↳ {cve}{RS}")

    if exposed:
        status_warn(f"{len(exposed)} serviço(s) com versão exposta:")
        for svc in exposed[:3]:
            print(f"      {YL}↳ Porta {svc['port']} — {svc['product']} {svc['version']}{RS}")

    if vt_flagged:
        status_err(f"VirusTotal: {summary.get('vt_malicious', 0)} engine(s) detectaram ameaça")

    if abuse_score >= 25:
        status_warn(f"AbuseIPDB: score de abuso {abuse_score}/100")

    if ssl_expired:
        status_err("Certificado SSL EXPIRADO")
    elif ssl_expiring:
        status_warn("Certificado SSL expira em menos de 30 dias")

    if server_banner:
        status_info(f"Banner: {server_banner}")

    if tech_stack:
        status_info(f"Stack: {', '.join(tech_stack[:4])}")

    if missing_headers:
        status_warn(f"Headers ausentes: {', '.join(missing_headers[:4])}")


def print_subdomain_summary(result: dict):
    if "error" in result:
        status_warn(f"Subdomain: {result['error']}")
        return

    active   = result.get("active_count", 0)
    dead     = result.get("dead_count", 0)
    takeover = result.get("takeover_candidates_count", 0)
    total    = result.get("total_found_crt", 0)

    print()
    status_ok(f"Subdomínios — {total} no crt.sh | {active} ativos | {dead} NXDOMAIN")

    if takeover:
        status_err(f"{takeover} candidato(s) a subdomain takeover:")
        for tc in result.get("takeover_candidates", [])[:5]:
            print(f"      {RD}↳ {tc['name']} → {tc['cname']}{RS}")
            print(f"         {DM}{tc['takeover_service']}{RS}")
    elif active == 0 and total == 0:
        status_info("Nenhum subdomínio encontrado no crt.sh")


def print_header_summary(result: dict):
    if "error" in result and not result.get("findings"):
        status_warn(f"Headers: {result['error']}")
        return

    summary  = result.get("summary", {})
    total    = summary.get("total_findings", 0)
    high     = summary.get("high", 0)
    medium   = summary.get("medium", 0)
    status   = result.get("status_code")

    print()
    status_color = GR if status and status < 400 else YL if status else DM
    print(f"  {DM}HTTP status:{RS} {status_color}{status or 'N/A'}{RS}  "
          f"| {DM}Findings:{RS} {total}  "
          f"({RD}{high} HIGH{RS} · {YL}{medium} MEDIUM{RS})")

    critical_findings = [
        f for f in result.get("findings", [])
        if f.get("severity") in ("HIGH", "CRITICAL")
    ]
    for f in critical_findings[:4]:
        color = RD if f["severity"] == "CRITICAL" else YL
        print(f"      {color}↳ [{f['severity']}] {f['title']}{RS}")
        print(f"         {DM}{f['mitre_id']} — {f['mitre_name']}{RS}")

def print_gov_summary(result: dict):
    if "error" in result:
        status_warn(f"Gov Agent: {result['error']}")
        return

    summary  = result.get("summary", {})
    risk     = summary.get("risk_level", "UNKNOWN")
    sanction = summary.get("sanction_count", 0)
    contracts = summary.get("total_contracts", 0)
    value    = summary.get("total_contract_value", 0.0)
    convenios = summary.get("total_convenios", 0)

    risk_color = RD if risk == "CRITICAL" else YL if risk == "HIGH" else GR if risk == "LOW" else CY

    print()
    label("CNPJ          :", result.get("cnpj_formatted", "—"))
    label("Risco Gov     :", risk, color=risk_color)
    label("Contratos     :", f"{contracts}  (R$ {value:,.2f})")
    label("Convênios     :", str(convenios))
    label("Sanções       :", str(sanction), color=RD if sanction else GR)

    if sanction:
        all_s = result.get("sanctions_ceis", []) + result.get("sanctions_cnep", [])
        for s in all_s[:3]:
            tipo = s.get("type", "?")
            desc = s.get("sanction_type", s.get("tipoSancao", "?"))
            org  = s.get("sanctioning_organ", s.get("orgaoSancionador", "?"))
            print(f"      {RD}↳ [{tipo}] {desc} — {org}{RS}")

    findings = result.get("gov_intel_findings", [])
    if findings:
        print()
        status_warn(f"{len(findings)} finding(s) governamental(is):")
        for f in findings[:3]:
            sev   = f.get("severity", "?")
            title = f.get("title", "?")
            color = RD if sev == "CRITICAL" else YL if sev == "HIGH" else DM
            print(f"    {color}● [{sev}]{RS} {title}")


# ── PIPELINE ─────────────────────────────────────────────────


def process_single_target(
    target: str,
    idx: int,
    total: int,
    correlator_snapshot: dict | None,
    enable_subdomains: bool = False,
    resolved: dict = None,
) -> dict | None:

    # Banner com tipo detectado
    input_label = ""
    if resolved:
        type_labels = {
            "domain": "DOMÍNIO",
            "ip":     "IP DIRETO",
            "url":    "URL",
            "email":  "E-MAIL",
        }
        tipo = type_labels.get(resolved["original_type"], resolved["original_type"].upper())
        input_label = f" [{tipo}]"
        if resolved["original_type"] != resolved["target_type"]:
            input_label += f"  {DM}({resolved['routing_note']}){RS}"

    header_section(f"ALVO {idx}/{total} — {target.upper()}")

    collect       = _load_agent("collector")
    validate      = _load_agent("validator")
    report        = _load_agent("reporter")
    infra_scan    = _load_agent("infra_agent")
    enrich        = _load_agent("enrichment_agent")
    subdomain     = _load_agent("subdomain_agent")
    header_check  = _load_agent("header_agent")
    analyze       = _load_agent("ai_analyst")
    intel_report  = _load_agent("intel_reporter")

    # coleta
    status_info("Coletando WHOIS e DNS...")
    dados = collect(target)

    # TXT Intelligence — extrai tecnologia e superfície de ataque dos registros TXT
    txt_records   = dados.get("dns", {}).get("TXT", [])
    txt_intel     = parse_txt(txt_records)
    if txt_intel["total_services"] > 0:
        status_info(
            f"TXT Intelligence — {txt_intel['total_services']} serviço(s) detectado(s): "
            f"{', '.join(txt_intel['categories_found'])}"
        )
        if "HIGH" in txt_intel["email_security_risk"] or "CRITICAL" in txt_intel["email_security_risk"]:
            status_warn(f"E-mail security: {txt_intel['email_security_risk']}")

        if "error" in dados and not dados.get("domain") and not dados.get("ip"):
            status_err(f"Coleta falhou: {dados['error']}")
            return None

    # validação
    # DEPOIS
    validacao = validate(dados)
    score     = validacao.get("confidence_score", 0)

    if not validacao.get("approved"):
        status_err(f"Reprovado — DNS não resolveu, análise impossível")
        return None

    # Warnings de qualidade (WHOIS parcial, score baixo) — não bloqueiam
    for w in validacao.get("warnings", []):
        status_warn(w)

    qualifier = "" if score >= 70 else " com ressalvas"
    status_ok(f"Validado{qualifier} — confiança {score}/100")

    # relatório base
    status_info("Gerando relatório base...")
    try:
        caminhos = report(dados, validacao)
        status_ok(f"Relatório → {caminhos.get('markdown', 'gerado')}")
    except Exception as e:
        status_warn(f"Relatório base falhou (não crítico): {e}")

    # reconhecimento de infraestrutura
    infra_result = None
    target_type  = dados.get("target_type", "domain")
    ips          = [target] if target_type == "ip" else dados.get("dns", {}).get("A", [])

    if ips:
        print()
        status_info(f"Reconhecimento de infraestrutura em {len(ips)} IP(s)...")
        for ip in ips:
            status_info(f"Escaneando {ip}")
            infra_result = infra_scan(ip)
            print_infra_result(infra_result)
    else:
        status_warn("Nenhum IP resolvido — reconhecimento de infra ignorado")

    # enriquecimento de inteligência
    print()
    status_info("Enriquecendo dados (subdomínios, CVEs, fingerprint, reputação)...")
    enrich_data = None
    try:
        enrich_data = enrich(
            collected_data=dados,
            ips=ips if ips else None,
            infra_data=infra_result,
        )
        print_enrichment_summary(enrich_data.get("summary", {}))
    except Exception as e:
        status_warn(f"Enriquecimento falhou (não crítico): {e}")

    # enumeração de subdomínios (somente para domínios, opcional)
    subdomain_result: dict = {}
    if enable_subdomains and target_type == "domain":
        print()
        status_info("Enumerando subdomínios (crt.sh + DNS)...")
        try:
            subdomain_result = subdomain(domain=target)
            print_subdomain_summary(subdomain_result)
        except Exception as e:
            status_warn(f"Subdomain agent falhou (não crítico): {e}")
            subdomain_result = {"error": str(e)}
    elif enable_subdomains and target_type == "ip":
        status_info("Subdomínios ignorados — alvo é IP, não domínio")

    # análise de headers HTTP
    print()
    status_info("Analisando headers HTTP...")
    header_result: dict = {}
    try:
        header_result = header_check(target=target)
        print_header_summary(header_result)
    except Exception as e:
        status_warn(f"Header agent falhou (não crítico): {e}")
        header_result = {"error": str(e)}

    # análise de IA
    print()
    status_info("Executando análise de inteligência...")
    ai_result = analyze(
        collected_data  = dados,
        validation      = validacao,
        shodan_data     = infra_result,
        correlator_data = correlator_snapshot,
        enrichment_data = enrich_data,
        subdomain_data  = subdomain_result or None,
        header_data     = header_result or None,
    )

    # ── extração compatível com schema v1 (string) e v2 (dict) ──
    exec_summ = ai_result.get("executive_summary", {})

    if isinstance(exec_summ, dict):
        priority  = exec_summ.get("risk_level") or ai_result.get("priority_level", "INDETERMINADO")
        summ_text = exec_summ.get("risk_justification") or exec_summ.get("risk_level", "")
    else:
        priority  = ai_result.get("priority_level", "INDETERMINADO")
        summ_text = str(exec_summ) if exec_summ else ""

    findings = ai_result.get("findings", [])

    print()
    label("Prioridade :", priority,
          color=RD if priority in ("CRÍTICO", "CRITICAL") else
                YL if priority in ("ALTO", "HIGH")        else
                GR if priority in ("BAIXO", "LOW")        else CY)
    label("Achados    :", str(len(findings)))

    if summ_text:
        print(f"\n  {DM}{summ_text[:300]}{RS}")

    if findings:
        print()
        status_warn("Principais achados:")
        for f in findings[:5]:
            sev   = f.get("severity", "?")
            title = f.get("title", "?")
            color = RD if sev in ("CRÍTICO", "CRITICAL") else \
                    YL if sev in ("ALTO", "HIGH")         else DM

            mitre      = f.get("mitre_attack") or {}
            mitre_id   = mitre.get("technique_id") if isinstance(mitre, dict) else f.get("mitre_id")
            mitre_name = mitre.get("technique")    if isinstance(mitre, dict) else f.get("mitre_name")

            print(f"    {color}● [{sev}]{RS} {title}")
            if mitre_id:
                print(f"       {DM}{mitre_id} — {mitre_name or ''}{RS}")

    # hipóteses adversariais (v2)
    hypotheses = ai_result.get("attack_hypotheses", [])
    if hypotheses:
        print()
        status_warn(f"{len(hypotheses)} hipótese(s) adversarial(is):")
        for h in hypotheses[:3]:
            if isinstance(h, dict):
                name  = h.get("name", "?")
                prob  = h.get("probability", "")
                color = RD if prob == "HIGH" else YL if prob == "MEDIUM" else DM
                print(f"    {color}◆ {name}  [{prob}]{RS}")
                for step in h.get("kill_chain", [])[:3]:
                    if isinstance(step, dict):
                        print(f"       {DM}{step.get('step','?')}. {step.get('action','')}  "
                              f"[{step.get('mitre_ttp','')}]{RS}")
            else:
                print(f"    {DM}◆ {h}{RS}")

    # relatório de inteligência final
    print()
    status_info("Gerando relatório de inteligência...")
    report_path = None
    try:
        report_path = intel_report(
            analysis  = ai_result,
            raw_data  = {"collected": dados, "infra": infra_result},
        )
        status_ok(f"Relatório → {report_path}")
    except Exception as e:
        status_warn(f"Intel reporter falhou (não crítico): {e}")

    # ── persistência no SQLite ────────────────────────────────
    try:
        db = Database()
        db.save_analysis(
            target      = target,
            analysis    = ai_result,
            json_path   = ai_result.get("saved_to"),
            report_path = report_path,
        )
    except Exception as e:
        status_warn(f"Database index falhou (não crítico): {e}")

    return dados


def run_pipeline(targets: list[str], enable_subdomains: bool = False) -> list[dict]:
    state     = load_session(targets)
    completed = set(state.get("completed", []))
    aprovados = state.get("aprovados", [])
    total     = len(targets)

    correlate = _load_agent("correlator")

    for idx, raw_target in enumerate(targets, 1):

        if raw_target in completed:
            status_info(f"[{idx}/{total}] {raw_target} — já processado, pulando")
            continue

        # ── Resolve e roteia o input ──────────────────────────────────────
        resolved = normalize(raw_target)
        input_type = resolved["original_type"]

        # Tipos ainda não implementados — avisa e pula
        if input_type == "asn":
            print()
            line()
            status_warn(f"ASN detectado: {resolved['target']} — expansão de bloco em desenvolvimento")
            status_info("Disponível na Fase 3. Use IPs individuais por enquanto.")
            completed.add(raw_target)
            state["completed"] = list(completed)
            save_session(state, targets)
            continue

        if resolved.get("requires_gov_agent"):
            print()
            line()
            cnpj_fmt = resolved["metadata"].get("cnpj_formatted", resolved["target"])
            header_section(f"ALVO {idx}/{total} — GOV INTELLIGENCE — {cnpj_fmt}")

            gov_agent = _load_agent("gov_agent")
            status_info(f"Consultando Portal da Transparência para CNPJ {cnpj_fmt}...")

            gov_result = gov_agent(resolved)
            print_gov_summary(gov_result)

            # persiste no SQLite reaproveitando a estrutura de análise
            try:
                db = Database()
                db.save_analysis(
                    target      = resolved["target"],
                    analysis    = {"findings": gov_result.get("gov_intel_findings", []),
                                "executive_summary": gov_result.get("summary", {})},
                    json_path   = None,
                    report_path = None,
                )
            except Exception as e:
                status_warn(f"Database index falhou (não crítico): {e}")

            completed.add(raw_target)
            state["completed"] = list(completed)
            save_session(state, targets)
            continue

        # ── Pipeline padrão ───────────────────────────────────────────────
        correlator_snapshot = None
        if len(aprovados) >= 2:
            try:
                correlator_snapshot = correlate(aprovados)
            except Exception:
                correlator_snapshot = None

        resultado = process_single_target(
            target              = resolved["target"],
            idx                 = idx,
            total               = total,
            correlator_snapshot = correlator_snapshot,
            enable_subdomains   = enable_subdomains,
            resolved            = resolved,
        )

        if resultado:
            aprovados.append(resultado)

        state["completed"] = list(completed | {raw_target})
        state["aprovados"] = aprovados
        completed.add(raw_target)
        save_session(state, targets)

    return aprovados


def run_correlation(aprovados: list[dict]):
    if len(aprovados) < 2:
        return

    correlate = _load_agent("correlator")

    header_section("CORRELAÇÃO FINAL ENTRE ALVOS")
    status_info(f"Analisando {len(aprovados)} alvo(s)...")

    resultado = correlate(aprovados)
    high      = [c for c in resultado if c.get("correlation_score", 0) >= 50]

    if high:
        print()
        status_warn(f"{len(high)} correlação(ões) forte(s):")
        for c in high:
            pair  = " ↔ ".join(c["pair"])
            score = c["correlation_score"]
            print(f"\n    {YL}● {pair}{RS}  score {score}/100")
            if c.get("shared_ips"):
                print(f"      {DM}IPs: {c['shared_ips']}{RS}")
            if c.get("shared_nameservers"):
                print(f"      {DM}NS: {c['shared_nameservers']}{RS}")
            if c.get("same_registrar"):
                print(f"      {DM}Registrar: {c['registrar']}{RS}")
    else:
        status_info("Nenhuma correlação forte encontrada.")


def summary(aprovados: list[dict], targets: list[str]):
    header_section("RESUMO DA SESSÃO")
    label("Alvos analisados :", str(len(targets)))
    label("Aprovados        :", str(len(aprovados)))
    label("Reprovados       :", str(len(targets) - len(aprovados)))
    label("Relatórios em    :", "data/")
    label("Logs em          :", "logs/")
    label("Concluído em     :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    try:
        db  = Database()
        dbr = db.get_summary()
        print()
        label("DB — Alvos       :", str(dbr["total_targets"]))
        label("DB — Análises    :", str(dbr["total_analyses"]))
        label("DB — Findings    :", str(dbr["total_findings"]))
        label("DB — Críticos    :", str(dbr["critical_total"]), color=RD)
    except Exception:
        pass

    print()


# ── CLI FLAGS ────────────────────────────────────────────────

def _parse_cli_flags() -> argparse.Namespace:
    """
    Lê flags opcionais da CLI sem quebrar o fluxo interativo.
    Uso: python main.py --deep --cnpj 12345678000199
    Sem flags: comportamento 100% idêntico ao atual.
    parse_known_args ignora argumentos desconhecidos — não quebra nada.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--deep", action="store_true", default=False)
    parser.add_argument("--cnpj", default="")
    flags, _ = parser.parse_known_args()
    return flags


# ── DEEP MODE ────────────────────────────────────────────────

def run_deep_mode(aprovados: list[dict], flags: argparse.Namespace) -> None:
    """
    Executa o deep pipeline para cada alvo aprovado no pipeline padrão.
    Só chamado se --deep foi passado. Pipeline padrão nunca é afetado.
    """
    from core.deep_pipeline import run_deep

    header_section("DEEP INTELLIGENCE MODE")
    status_info(f"Processando {len(aprovados)} alvo(s) aprovado(s)...")

    if flags.cnpj:
        status_info(f"CNPJ fornecido: {flags.cnpj}")

    for target_data in aprovados:
        target_str = (
            target_data.get("domain")
            or target_data.get("ip")
            or target_data.get("target", "")
        )
        if not target_str:
            status_warn("Alvo sem domínio/IP identificável — pulando deep mode")
            continue

        print()
        line()
        status_info(f"Deep pipeline → {target_str}")

        deep_args = argparse.Namespace(
            target=target_str,
            cnpj=flags.cnpj,
        )

        try:
            result = run_deep(deep_args)
            risk   = result["metadata"]["risk_summary"]
            stats  = result["metadata"]["stats"]

            print()
            label("Nós no grafo   :", str(stats["total_nodes"]))
            label("Arestas        :", str(stats["total_edges"]))
            label("Correlações    :", str(stats["correlations"]))
            label("Risk score     :", str(risk["total_risk_score"]),
                  color=RD if risk["total_risk_score"] > 60 else
                        YL if risk["total_risk_score"] > 30 else GR)
            label("High risk nós  :", str(risk["high_risk_count"]),
                  color=RD if risk["high_risk_count"] > 0 else GR)
            label("Output         :", result["metadata"].get("output_path", "—"), color=DM)

            print()
            if risk.get("has_sanctioned_entity"):
                status_err("EMPRESA CONSTA NO CEIS/CNEP")
            if risk.get("has_cves"):
                status_warn("CVEs detectados na infraestrutura")
            if risk.get("has_high_abuse_ip"):
                status_warn("IP com score de abuso elevado (AbuseIPDB > 50)")
            if not any([
                risk.get("has_sanctioned_entity"),
                risk.get("has_cves"),
                risk.get("has_high_abuse_ip"),
            ]):
                status_ok("Nenhum indicador crítico detectado no deep scan")

        except Exception as e:
            status_warn(f"Deep pipeline falhou para {target_str}: {e}")


# ── ENTRY POINT ──────────────────────────────────────────────

if __name__ == "__main__":
    clear()
    banner()

    # Lê flags opcionais — não altera fluxo interativo
    flags = _parse_cli_flags()

    # Indica modo ativo no banner
    if flags.deep:
        status_info(f"Modo: {BLD}DEEP INTELLIGENCE{RS} ativo")
        if flags.cnpj:
            status_info(f"CNPJ: {flags.cnpj}")
        print()

    targets = input_targets()
    options = input_options()

    # Pipeline padrão — intocado
    aprovados = run_pipeline(targets, enable_subdomains=options["enable_subdomains"])

    run_correlation(aprovados)
    summary(aprovados, targets)

    clear_session(targets)

    # Deep mode — só executa se --deep foi passado e há alvos aprovados
    if flags.deep and aprovados:
        run_deep_mode(aprovados, flags)
    elif flags.deep and not aprovados:
        status_warn("Deep mode ativo mas nenhum alvo foi aprovado no pipeline padrão.")

    line(color=CY)
    print(f"\n  {DM}Sentinel OSINT — uso ético e responsável{RS}\n")