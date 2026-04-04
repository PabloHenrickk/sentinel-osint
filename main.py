from agents.collector import run as collect
from agents.validator import run as validate
from agents.reporter import run as report

if __name__ == "__main__":
    domain = input("Digite o domínio para investigar: ")

    # etapa 1 — coleta
    dados = collect(domain)

    # etapa 2 — validação
    validacao = validate(dados)

    # etapa 3 — relatório (só gera se aprovado)
    if validacao["approved"]:
        caminhos = report(dados, validacao)
        print(f"\n✅ Relatório gerado: {caminhos['markdown']}")
    else:
        print(f"\n❌ Domínio reprovado na validação. Score: {validacao['confidence_score']}/100")
        print("Relatório não gerado.")