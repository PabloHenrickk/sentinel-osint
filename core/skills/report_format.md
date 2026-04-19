# Skill — Report Format | Schema Obrigatório

## Contrato
Retorne APENAS JSON válido. Sem texto antes ou depois. Sem markdown fences (```json). Se um campo não tem dado: `null` para valores únicos, `[]` para arrays.

## Schema

```json
{
  "target": "string",
  "analyzed_at": "ISO 8601",
  "provider": "string",
  "model": "string",

  "threat_profile": {
    "target_value": "CRITICAL|HIGH|MEDIUM|LOW",
    "target_value_justification": "string",
    "primary_threat_actor": "APT|RANSOMWARE|HACKTIVISM|INSIDER|OPPORTUNISTIC",
    "threat_actor_motivation": "string",
    "attack_surface_category": "WEB|INFRASTRUCTURE|SUPPLY_CHAIN|HUMAN|MIXED"
  },

  "executive_summary": {
    "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "risk_justification": "string — 2-3 frases, linguagem executiva",
    "immediate_actions_required": ["string"],
    "key_attack_vectors": ["string — mínimo 2 itens"]
  },

  "findings": [
    {
      "id": "F-001",
      "title": "string — específico, não genérico",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "string",
      "cvss_estimate": "number 0-10 ou null",
      "mitre_attack": {
        "tactic": "string",
        "technique": "string",
        "technique_id": "string — T1xxx"
      },
      "technical_detail": {
        "what": "string",
        "where": "string — porta, endpoint ou header específico",
        "evidence": "string — dado exato coletado"
      },
      "adversarial_impact": {
        "immediate_risk": "string",
        "amplified_risk": "string",
        "data_at_risk": "string"
      },
      "exploitation": {
        "complexity": "NONE|LOW|MEDIUM|HIGH",
        "prerequisites": ["string"],
        "realistic_scenario": "string — passos numerados, mínimo 3 para MEDIUM+"
      },
      "recommendation": {
        "priority": "IMMEDIATE|SHORT_TERM|MEDIUM_TERM|MONITOR",
        "action": "string — verbo imperativo + objeto específico",
        "verification": "string — comando para confirmar correção"
      }
    }
  ],

  "attack_hypotheses": [
    {
      "id": "H-001",
      "name": "string",
      "threat_actor_profile": "string",
      "objective": "string",
      "prerequisites": ["string"],
      "kill_chain": [
        {"step": 1, "action": "string", "mitre_ttp": "T1xxx", "tool_example": "string"}
      ],
      "probability": "HIGH|MEDIUM|LOW",
      "probability_justification": "string",
      "potential_impact": "string",
      "detection_indicators": ["string"]
    }
  ],

  "infrastructure_intelligence": {
    "open_ports": [{"port": "number", "service": "string", "risk_assessment": "string"}],
    "cves_detected": [{"cve_id": "string", "cvss": "number", "description": "string"}],
    "cdn_detected": "boolean",
    "direct_ip_exposed": "boolean",
    "security_headers": {
      "missing": ["string"],
      "combined_risk": "string"
    },
    "email_security": {
      "spf_configured": "boolean|null",
      "dmarc_configured": "boolean|null",
      "email_spoofing_possible": "boolean",
      "spoofing_justification": "string"
    }
  },

  "blind_spots": [
    {
      "area": "string",
      "reason": "string",
      "impact_on_analysis": "string",
      "collection_method": "string"
    }
  ],

  "prioritized_recommendations": [
    {
      "priority": 1,
      "timeframe": "< 24h|< 7 dias|< 30 dias|Monitorar",
      "action": "string",
      "addresses_findings": ["F-001"]
    }
  ],

  "confidence_assessment": {
    "overall_confidence": "HIGH|MEDIUM|LOW",
    "data_completeness": "number 0-100",
    "limiting_factors": ["string"]
  }
}
```

## Validação antes de retornar
1. JSON é válido? (sem vírgula final, aspas corretas, chaves fechadas)
2. Todos os findings têm `technique_id` preenchido?
3. `executive_summary.key_attack_vectors` tem ≥ 2 itens?
4. `attack_hypotheses` tem ≥ 2 hipóteses?
5. Nenhum finding MEDIUM+ com `realistic_scenario` vago ou com menos de 3 passos?