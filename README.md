# 🛡️ Sentinel OSINT

> Plataforma modular de automação OSINT com agentes especializados em Python.

![Status](https://img.shields.io/badge/status-em%20desenvolvimento-yellow)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## O que é

Sentinel OSINT é um sistema de agentes Python que automatiza coleta,
validação e correlação de dados de inteligência de fontes abertas (OSINT).

O Claude atua como orquestrador, acionando agentes especializados para
investigações digitais sobre domínios, IPs, e-mails e organizações.

## Arquitetura

sentinel-osint/
├── agents/      → agentes especializados (collector, validator, correlator)
├── core/        → funções compartilhadas (logs, output, config)
├── data/        → relatórios gerados (não versionado)
├── docs/        → documentação técnica
├── tests/       → testes automatizados
└── main.py      → orquestrador principal

## Agentes

| Agente | Responsabilidade |
|---|---|
| `collector` | Coleta dados de domínio, IP, e-mail via APIs públicas |
| `validator` | Valida formato e confiabilidade dos dados coletados |
| `correlator` | Cruza entidades entre fontes diferentes |
| `reporter` | Gera relatório estruturado em JSON e Markdown |

## Tecnologias

- Python 3.11+
- theHarvester
- Shodan API
- WHOIS / DNS lookup
- Anthropic Claude API

## Como rodar
```bash
# clonar o repo
git clone https://github.com/PabloHenrickk/sentinel-osint.git
cd sentinel-osint

# instalar dependências
pip install -r requirements.txt

# rodar
python main.py
```

## Roadmap

- [x] Estrutura do projeto
- [ ] Agent Collector (domínio + WHOIS)
- [ ] Agent Validator
- [ ] Agent Correlator
- [ ] Agent Reporter
- [ ] Integração com Claude como orquestrador
- [ ] Interface de linha de comando (CLI)

## Autor

Desenvolvido por **Pablo** — estudante de Python e Cybersecurity.