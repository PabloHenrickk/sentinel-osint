import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from agents.ai_analyst   import run as analyze
from agents.collector    import run as collect
from agents.validator    import run as validate
from agents.reporter     import run as report
from agents.correlator   import run as correlate
from agents.shodan_agent import run as shodan_scan

# ── CORES ANSI ──────────────────────────────────────────────
CY  = "\033[96m"
GR  = "\033[92m"
RD  = "\033[91m"
YL  = "\033[93m"
DM  = "\033[2m"
BLD = "\033[1m"
RS  = "\033[0m"

SESSION_DIR = Path("data/sessions")


# ── CHECKPOINT ──────────────────────────────────────────────

def _session_path(targets: list[str]) -> Path:
    """Gera caminho único por sessão baseado nos alvos."""
    key = "_".join(sorted(targets))[:60].replace("/", "-")
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    return SESSION_DIR / f"session_{key}.json"


def load_session(targets: list[str]) -> dict:
    """
    Carrega sessão existente ou retorna estado vazio.
    Permite retomar batch interrompido sem reprocessar alvos já concluídos.
    """
    path = _session_path(targets)
    if path.exists():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            completed = state.get("completed", [])
            if completed:
                print(f"  {YL}⚠{RS}  Sessão retomada — {len(completed)} alvo(s) já processado(s)")
            return state
        except Exception:
            pass
    return {"completed": [], "aprovados": [], "targets": targets}


def save_session(state: dict, targets: list[str]) -> None:
    """Persiste estado da sessão após cada alvo processado."""
    path = _session_path(targets)
    try:
        path.write_text(
            json.dumps(state, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception as e:
        print(f"  {YL}⚠{RS}  Falha ao salvar checkpoint: {e}")


def clear_session(targets: list[str]) -> None:
    """Remove arquivo de sessão após conclusão bem-sucedida."""
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
    print(f"  {DM}Domínios, IPs ou mix separados por vírgula.{RS}")
    print(f"  {DM}Exemplos: google.com  |  8.8.8.8  |  github.com, 1.1.1.1{RS}\n")
    raw = input(f"  {BLD}>{RS} ").strip()
    if not raw:
        status_err("Nenhum alvo informado.")
        sys.exit(1)
    return [t.strip() for t in raw.split(",") if t.strip()]


def print_shodan_result(result: dict):
    if "error" in result:
        status_warn(f"Shodan: {result['error']}")
        return
    print()
    label("Organização",   result.get("organization", "—"))
    label("País / Cidade", f"{result.get('country','—')} / {result.get('city','—')}")
    label("Sistema Op.",   result.get("os") or "—")
    label("Portas abertas", str(result.get("open_ports", [])))
    vulns = result.get("vulns", [])
    label("CVEs", ", ".join(vulns) if vulns else "Nenhum indexado",
          color=RD if vulns else DM)
    services = result.get("services", [])
    critical = [s for s in services if s["severity"] == "CRÍTICO"]
    if critical:
        print()
        status_warn(f"{len(critical)} serviço(s) CRÍTICO(s):")
        for s in critical:
            print(f"      {RD}● Porta {s['port']} — {s['description']}{RS}")
            if s.get("mitre"):
                m = s["mitre"]
                print(f"        {DM}{m['technique_id']} — {m['technique_name']}{RS}")


# ── PIPELINE ─────────────────────────────────────────────────

def process_single_target(
    target: str,
    idx: int,
    total: int,
    correlator_snapshot: dict | None,
) -> dict | None:
    """
    Executa o pipeline completo em um único alvo.

    Retorna dict com dados aprovados, ou None se reprovado.
    Recebe correlator_snapshot dos alvos JÁ processados — 
    permite que o ai_analyst considere correlações parciais.
    """
    header_section(f"ALVO {idx}/{total} — {target.upper()}")

    # coleta
    status_info("Coletando WHOIS e DNS...")
    dados = collect(target)

    # validação
    validacao = validate(dados)
    score     = validacao["confidence_score"]

    if not validacao["approved"]:
        status_err(f"Reprovado — score {score}/100")
        return None

    status_ok(f"Validado — confiança {score}/100")

    # relatório base
    status_info("Gerando relatório base...")
    caminhos = report(dados, validacao)
    status_ok(f"Relatório → {caminhos['markdown']}")

    # shodan
    shodan_result = None
    ips = dados.get("dns", {}).get("A", [])
    if ips:
        print()
        status_info(f"Reconhecimento Shodan em {len(ips)} IP(s)...")
        for ip in ips:
            status_info(f"Escaneando {ip}")
            shodan_result = shodan_scan(ip)
            print_shodan_result(shodan_result)
    else:
        status_warn("Nenhum IP resolvido — Shodan ignorado")

    # análise de IA — agora recebe correlator_snapshot
    print()
    status_info("Executando análise de inteligência...")
    ai_result = analyze(
        collected_data  = dados,
        validation      = validacao,
        shodan_data     = shodan_result if ips else None,
        correlator_data = correlator_snapshot,  # ← bug corrigido
    )

    priority = ai_result.get("priority_level", "?")
    findings = ai_result.get("findings", [])
    summ     = ai_result.get("executive_summary", "")

    print()
    label("Prioridade :", priority,
          color=RD if priority == "CRÍTICO" else
                YL if priority == "ALTO"    else
                GR if priority == "BAIXO"   else CY)
    label("Achados    :", str(len(findings)))

    if summ:
        print(f"\n  {DM}{summ[:200]}{RS}")

    if findings:
        print()
        status_warn("Principais achados:")
        for f in findings[:3]:
            sev   = f.get("severity", "?")
            title = f.get("title", "?")
            print(f"    {RD if sev == 'CRÍTICO' else YL}● [{sev}]{RS} {title}")

    return dados


def run_pipeline(targets: list[str]) -> list[dict]:
    """
    Executa pipeline com checkpoint por alvo.

    - Retoma sessão interrompida automaticamente
    - Correlação parcial alimenta o ai_analyst em tempo real
    - Salva estado após cada alvo concluído
    """
    state    = load_session(targets)
    completed = set(state.get("completed", []))
    aprovados = state.get("aprovados", [])
    total     = len(targets)

    for idx, target in enumerate(targets, 1):

        # pula alvos já processados na sessão anterior
        if target in completed:
            status_info(f"[{idx}/{total}] {target} — já processado, pulando")
            continue

        # correlação parcial dos aprovados até agora
        correlator_snapshot = None
        if len(aprovados) >= 2:
            try:
                correlator_snapshot = correlate(aprovados)
            except Exception:
                correlator_snapshot = None

        resultado = process_single_target(
            target              = target,
            idx                 = idx,
            total               = total,
            correlator_snapshot = correlator_snapshot,
        )

        if resultado:
            aprovados.append(resultado)

        # checkpoint — salva estado mesmo se o alvo foi reprovado
        state["completed"] = list(completed | {target})
        state["aprovados"] = aprovados
        completed.add(target)
        save_session(state, targets)

    return aprovados


def run_correlation(aprovados: list[dict]):
    """Correlação final com todos os alvos aprovados."""
    if len(aprovados) < 2:
        return

    header_section("CORRELAÇÃO FINAL ENTRE ALVOS")
    status_info(f"Analisando {len(aprovados)} alvo(s)...")

    resultado = correlate(aprovados)
    high = resultado.get("high_correlations", [])

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
    print()


if __name__ == "__main__":
    clear()
    banner()

    targets   = input_targets()
    aprovados = run_pipeline(targets)

    run_correlation(aprovados)
    summary(aprovados, targets)

    # limpa sessão apenas após conclusão total
    clear_session(targets)

    line(color=CY)
    print(f"\n  {DM}Sentinel OSINT — uso ético e responsável!{RS}\n")