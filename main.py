from agents.collector import run as collect
from agents.validator import run as validate
from agents.reporter import run as report
from agents.correlator import run as correlate

if __name__ == "__main__":
    print("=== Sentinel OSINT ===\n")

    # coleta múltiplos domínios
    entrada = input("Digite domínios separados por vírgula: ")
    dominios = [d.strip() for d in entrada.split(",")]

    aprovados = []

    for domain in dominios:
        print(f"\n--- Processando: {domain} ---")

        # coleta
        dados = collect(domain)

        # valida
        validacao = validate(dados)

        # só aprova se passou na validação
        if validacao["approved"]:
            aprovados.append(dados)
            report(dados, validacao)
        else:
            print(f"❌ {domain} reprovado — score {validacao['confidence_score']}/100")

    # correlaciona se tiver mais de um aprovado
    print(f"\n--- Correlação ---")
    if len(aprovados) >= 2:
        resultado = correlate(aprovados)
        print(f"\nPares analisados: {resultado['total_pairs']}")
        if resultado["high_correlations"]:
            print("🔴 Correlações fortes encontradas:")
            for c in resultado["high_correlations"]:
                print(f"  {c['pair']} — score {c['correlation_score']}/100")
                if c["shared_ips"]:
                    print(f"  IPs compartilhados: {c['shared_ips']}")
    else:
        print("Mínimo 2 domínios aprovados necessários para correlação.")