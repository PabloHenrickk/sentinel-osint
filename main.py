import os
import sys
import time
from datetime import datetime
from agents.ai_analyst import run as analyze

from agents.collector    import run as collect
from agents.validator    import run as validate
from agents.reporter     import run as report
from agents.correlator   import run as correlate
from agents.shodan_agent import run as shodan_scan


# ── CORES ANSI ──────────────────────────────────────────────
CY  = "\033[96m"   # cyana
GR  = "\033[92m"   # verde
RD  = "\033[91m"   # vermelho
YL  = "\033[93m"   # amarelo
DM  = "\033[2m"    # dimmed
BLD = "\033[1m"    # bold
RS  = "\033[0m"    # reset


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
    print(f"  {DM}{text:<16}{RS}{color}{value}{RS}")


def status_ok(msg: str):
    print(f"  {GR}✔{RS}  {msg}")


def status_warn(msg: str):
    print(f"  {YL}⚠{RS}  {msg}")


def status_err(msg: str):
    print(f"  {RD}✖{RS}  {msg}")


def status_info(msg: str):
    print(f"  {CY}→{RS}  {msg}")


def header_section(title: str):
    print()
    line()
    print(f"  {BLD}{title}{RS}")
    line()


def input_targets() -> list[str]:
    """
    Tela de entrada de alvos com instruções claras.
    """
    print(f"\n  {CY}ALVOS{RS}")
    print(f"  {DM}Domínios, IPs ou mix separados por vírgula.{RS}")
    print(f"  {DM}Exemplos: google.com  |  8.8.8.8  |  github.com, 1.1.1.1{RS}\n")
    raw = input(f"  {BLD}>{RS} ").strip()

    if not raw:
        status_err("Nenhum alvo informado.")
        sys.exit(1)

    targets = [t.strip() for t in raw.split(",") if t.strip()]
    return targets


def print_shodan_result(result: dict):
    if "error" in result:
        status_warn(f"Shodan: {result['error']}")
        return

    print()
    label("Organização",  result.get("organization", "—"))
    label("País / Cidade", f"{result.get('country','—')} / {result.get('city','—')}")
    label("Sistema Op.",  result.get("os") or "—")
    label("Portas abertas", str(result.get("open_ports", [])))

    vulns = result.get("vulns", [])
    if vulns:
        label("CVEs",  ", ".join(vulns), color=RD)
    else:
        label("CVEs", "Nenhum indexado", color=DM)

    services = result.get("services", [])
    critical = [s for s in services if s["severity"] == "CRÍTICO"]
    if critical:
        print()
        status_warn(f"{len(critical)} serviço(s) CRÍTICO(s) encontrado(s):")
        for s in critical:
            print(f"      {RD}● Porta {s['port']} — {s['description']}{RS}")
            if s.get("mitre"):
                m = s["mitre"]
                print(f"        {DM}{m['technique_id']} — {m['technique_name']}{RS}")


def run_pipeline(targets: list[str]) -> list[dict]:
    """
    Executa o pipeline completo para cada alvo.
    Retorna lista de dados aprovados para correlação.
    """
    aprovados = []
    total     = len(targets)

    for idx, target in enumerate(targets, 1):
        header_section(f"ALVO {idx}/{total} — {target.upper()}")

        # coleta
        status_info("Coletando WHOIS e DNS...")
        dados = collect(target)

        # validação
        validacao = validate(dados)
        score     = validacao["confidence_score"]

        if not validacao["approved"]:
            status_err(f"Reprovado na validação — score {score}/100")
            continue

        status_ok(f"Validado — confiança {score}/100")

        # relatório base
        status_info("Gerando relatório base...")
        caminhos = report(dados, validacao)
        status_ok(f"Relatório salvo → {caminhos['markdown']}")

        aprovados.append(dados)

        # shodan
        shodan_result = None
        ips = dados.get("dns", {}).get("A", [])
        if ips:
            print()
            status_info(f"Iniciando reconhecimento Shodan em {len(ips)} IP(s)...")
            for ip in ips:
                status_info(f"Escaneando {ip}")
                shodan_result = shodan_scan(ip)
                print_shodan_result(shodan_result)
        else:
            status_warn("Nenhum IP resolvido — Shodan ignorado")

        # análise de IA
        print()
        status_info("Executando análise de inteligência...")
        ai_result = analyze(
            collected_data=dados,
            validation=validacao,
            shodan_data=shodan_result if ips else None,
        )

        priority = ai_result.get("priority_level", "?")
        findings = ai_result.get("findings", [])
        summ     = ai_result.get("executive_summary", "")

        print()
        label("Prioridade :", priority,
              color=RD if priority == "CRÍTICO" else
                    YL if priority == "ALTO" else
                    GR if priority == "BAIXO" else CY)
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

    return aprovados

def run_correlation(aprovados: list[dict]):
    """
    Executa correlação se houver múltiplos alvos aprovados.
    """
    if len(aprovados) < 2:
        return

    header_section("CORRELAÇÃO ENTRE ALVOS")
    status_info(f"Analisando {len(aprovados)} alvo(s)...")

    resultado = correlate(aprovados)

    high = resultado.get("high_correlations", [])
    if high:
        print()
        status_warn(f"{len(high)} correlação(ões) forte(s) encontrada(s):")
        for c in high:
            pair  = " ↔ ".join(c["pair"])
            score = c["correlation_score"]
            print(f"\n    {YL}● {pair}{RS}  score {score}/100")
            if c.get("shared_ips"):
                print(f"      {DM}IPs compartilhados: {c['shared_ips']}{RS}")
            if c.get("shared_nameservers"):
                print(f"      {DM}NS compartilhados: {c['shared_nameservers']}{RS}")
            if c.get("same_registrar"):
                print(f"      {DM}Mesmo registrar: {c['registrar']}{RS}")
    else:
        status_info("Nenhuma correlação forte encontrada entre os alvos.")


def summary(aprovados: list[dict], targets: list[str]):
    """
    Resumo final da sessão.
    """
    header_section("RESUMO DA SESSÃO")
    label("Alvos analisados :", str(len(targets)))
    label("Alvos aprovados  :", str(len(aprovados)))
    label("Alvos reprovados :", str(len(targets) - len(aprovados)))
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

    line(color=CY)
    print(f"\n  {DM}Sentinel OSINT — uso ético e responsável{RS}\n")