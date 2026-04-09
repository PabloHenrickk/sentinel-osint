import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# ── CORES ANSI ──────────────────────────────────────────────
CY  = "\033[96m"
GR  = "\033[92m"
RD  = "\033[91m"
YL  = "\033[93m"
DM  = "\033[2m"
BLD = "\033[1m"
RS  = "\033[0m"

SESSION_DIR = Path("data/sessions")


# ── IMPORTS LAZY — carrega agente só quando for usar ─────────
# Motivo: se um agente tiver erro de sintaxe ou dependência
# faltando, o sistema não cai inteiro antes do banner.
# O erro aparece no momento exato em que o agente é chamado,
# com contexto claro de qual alvo estava sendo processado.

def _load_agent(name: str):
    """
    Importa um agente pelo nome e retorna sua função run().
    Em caso de erro, retorna uma função que reporta a falha
    sem travar o pipeline.
    """
    try:
        import importlib
        module = importlib.import_module(f"agents.{name}")
        return module.run
    except ImportError as e:
        # dependência faltando (ex: pacote não instalado)
        def _agent_unavailable(*args, **kwargs):
            return {"error": f"Agente '{name}' indisponível: {e}"}
        print(f"  {YL}⚠{RS}  Agente '{name}' não carregado: {e}")
        return _agent_unavailable
    except SyntaxError as e:
        # erro de sintaxe no código do agente
        def _agent_broken(*args, **kwargs):
            return {"error": f"Agente '{name}' com erro de sintaxe: {e}"}
        print(f"  {RD}✖{RS}  Agente '{name}' com erro de sintaxe: {e}")
        return _agent_broken


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


def print_infra_result(result: dict):
    """Exibe resultado do infra_agent (substitui print_shodan_result)."""
    if "error" in result and not result.get("open_ports"):
        status_warn(f"Infra: {result['error']}")
        # se houve fallback parcial, mostra qual provider foi usado
        if result.get("provider_errors"):
            for err in result["provider_errors"]:
                print(f"      {DM}✖ {err}{RS}")
        return

    provider = result.get("provider_used", "desconhecido")
    cdn      = result.get("cdn_detected")

    print()
    label("Provider usado",  provider,                          color=DM)
    label("Organização",     result.get("organization", "—"))
    label("País / Cidade",   f"{result.get('country','—')} / {result.get('city','—')}")
    label("ASN",             result.get("asn") or "—",          color=DM)
    label("Sistema Op.",     result.get("os") or "—",           color=DM)
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


# ── PIPELINE ─────────────────────────────────────────────────

def process_single_target(
    target: str,
    idx: int,
    total: int,
    correlator_snapshot: dict | None,
) -> dict | None:
    """
    Executa o pipeline completo em um único alvo.
    Carrega cada agente com lazy import — falha de um não derruba os outros.
    """
    header_section(f"ALVO {idx}/{total} — {target.upper()}")

    # carrega agentes com lazy import
    collect    = _load_agent("collector")
    validate   = _load_agent("validator")
    report     = _load_agent("reporter")
    infra_scan = _load_agent("infra_agent")
    analyze    = _load_agent("ai_analyst")

    # coleta
    status_info("Coletando WHOIS e DNS...")
    dados = collect(target)

    # para se a coleta falhar completamente
    if "error" in dados and not dados.get("domain") and not dados.get("ip"):
        status_err(f"Coleta falhou: {dados['error']}")
        return None

    # validação
    validacao = validate(dados)
    score     = validacao.get("confidence_score", 0)

    if not validacao.get("approved"):
        status_err(f"Reprovado — score {score}/100")
        return None

    status_ok(f"Validado — confiança {score}/100")

    # relatório base
    status_info("Gerando relatório base...")
    try:
        caminhos = report(dados, validacao)
        status_ok(f"Relatório → {caminhos.get('markdown', 'gerado')}")
    except Exception as e:
        status_warn(f"Relatório base falhou (não crítico): {e}")

    # reconhecimento de infraestrutura
    # para domínio: usa IPs resolvidos pelo DNS
    # para IP direto: usa o próprio alvo
    infra_result = None
    target_type  = dados.get("target_type", "domain")

    if target_type == "ip":
        ips = [target]
    else:
        ips = dados.get("dns", {}).get("A", [])

    if ips:
        print()
        status_info(f"Reconhecimento de infraestrutura em {len(ips)} IP(s)...")
        for ip in ips:
            status_info(f"Escaneando {ip}")
            infra_result = infra_scan(ip)
            print_infra_result(infra_result)
    else:
        status_warn("Nenhum IP resolvido — reconhecimento de infra ignorado")

    # análise de IA
    print()
    status_info("Executando análise de inteligência...")
    ai_result = analyze(
        collected_data  = dados,
        validation      = validacao,
        shodan_data     = infra_result,       # nome mantido para compatibilidade com ai_analyst
        correlator_data = correlator_snapshot,
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
    Retoma sessão interrompida automaticamente.
    """
    state     = load_session(targets)
    completed = set(state.get("completed", []))
    aprovados = state.get("aprovados", [])
    total     = len(targets)

    # carrega correlator uma vez (usado em todo o loop)
    correlate = _load_agent("correlator")

    for idx, target in enumerate(targets, 1):

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

        state["completed"] = list(completed | {target})
        state["aprovados"] = aprovados
        completed.add(target)
        save_session(state, targets)

    return aprovados


def run_correlation(aprovados: list[dict]):
    """Correlação final com todos os alvos aprovados."""
    if len(aprovados) < 2:
        return

    correlate = _load_agent("correlator")

    header_section("CORRELAÇÃO FINAL ENTRE ALVOS")
    status_info(f"Analisando {len(aprovados)} alvo(s)...")

    resultado = correlate(aprovados)
    high      = resultado.get("high_correlations", [])

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

    # agentes carregados APÓS o banner — erro aparece com contexto visual
    targets   = input_targets()
    aprovados = run_pipeline(targets)

    run_correlation(aprovados)
    summary(aprovados, targets)

    clear_session(targets)

    line(color=CY)
    print(f"\n  {DM}Sentinel OSINT — uso ético e responsável{RS}\n")