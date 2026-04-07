# Report Format — Skill de Output

## Formato JSON obrigatório
Sempre retornar JSON válido.
Sem texto antes ou depois do JSON.
Sem markdown. Sem blocos de código.

## Schema obrigatório
{
  "target": "string",
  "priority_level": "CRÍTICO|ALTO|MÉDIO|BAIXO|INFO",
  "executive_summary": "string — 2 a 4 frases",
  "findings": [
    {
      "id": "F001",
      "title": "string",
      "severity": "CRÍTICO|ALTO|MÉDIO|BAIXO|INFO",
      "description": "string",
      "evidence": "string — dado específico que suporta o achado",
      "attack_complexity": "TRIVIAL|BAIXA|MÉDIA|ALTA",
      "mitre_technique": "Txxxx — Nome da técnica",
      "recommendation": "string — ação concreta",
      "confidence": "ALTA|MÉDIA|BAIXA"
    }
  ],
  "correlations": ["string"],
  "threat_hypotheses": ["string"],
  "data_gaps": ["string"],
  "next_steps": ["string"]
}

## Regras de qualidade
- evidence SEMPRE com dado específico (porta, versão, IP, banner)
- recommendation SEMPRE com verbo de ação
- threat_hypotheses SEMPRE com "Indica possível..." ou "Sugere..."
- Mínimo 1 finding por análise
- Máximo 10 findings por análise
- next_steps focados em OSINT — sem ações destrutivas