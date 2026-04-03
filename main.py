from agents.collector import run

if __name__ == "__main__":
    domain = input("Digite o domínio para investigar: ")
    resultado = run(domain)
    print("\n--- RESULTADO ---")
    print(f"WHOIS: {resultado['whois']}")
    print(f"DNS A:  {resultado['dns'].get('A', [])}")