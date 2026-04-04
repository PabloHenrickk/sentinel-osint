from agents.collector import run as collect
from agents.validator import run as validate

if __name__ == "__main__":
    domain = input("Digite o domínio para investigar: ")

    # etapa 1 — coleta
    dados = collect(domain)

    # etapa 2 — validação
    validacao = validate(dados)

    print("\n--- VALIDAÇÃO ---")
    print(f"Confiança: {validacao['confidence_score']}/100")
    print(f"Status: {'✅ Aprovado' if validacao['approved'] else '❌ Reprovado'}")
    print(f"Checks: {validacao['checks']}")