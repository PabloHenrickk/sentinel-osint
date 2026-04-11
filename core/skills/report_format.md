# Skill — Report Format | Schema de Output Obrigatório

## Contrato de Output

Você SEMPRE retorna JSON válido. Sem texto antes do JSON. Sem texto depois do JSON. Sem markdown fences (```json). Apenas o objeto JSON.

Se não conseguir completar uma seção, preencha com o campo vazio mas mantenha a chave. Nunca omita chaves do schema.

---

## Schema Completo — Versão 2.0

```json
{
  "target": "string — domínio ou IP analisado",
  "analysis_timestamp": "ISO 8601",
  "analyst_model": "string — modelo LLM usado",
  
  "threat_profile": {
    "target_value": "CRITICAL | HIGH | MEDIUM | LOW",
    "target_value_justification": "string — por que esse alvo tem esse valor para atacantes",
    "primary_threat_actor": "APT | RANSOMWARE | HACKTIVISM | INSIDER | OPPORTUNISTIC | MULTIPLE",
    "threat_actor_motivation": "string — o que um atacante buscaria nesse alvo",
    "attack_surface_category": "WEB | INFRASTRUCTURE | SUPPLY_CHAIN | HUMAN | MIXED"
  },

  "executive_summary": {
    "risk_level": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
    "risk_justification": "string — 2-3 frases explicando o nível de risco, linguagem executiva",
    "immediate_actions_required": ["string — ações que precisam acontecer nas próximas 24h"],
    "key_attack_vectors": ["string — vetores principais identificados, linguagem técnica direta"]
  },

  "findings": [
    {
      "id": "F-001",
      "title": "string — título direto do achado",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "cvss_estimate": "number 0.0-10.0 — estimativa quando aplicável, null se não aplicável",
      "category": "EXPOSURE | MISCONFIGURATION | VULNERABILITY | INFORMATION_DISCLOSURE | WEAK_POLICY",
      
      "technical_detail": {
        "what": "string — o que foi encontrado, dados concretos",
        "where": "string — porta, endpoint, header, serviço específico",
        "evidence": "string — dado exato coletado que comprova o achado"
      },
      
      "adversarial_impact": {
        "immediate_risk": "string — o que um atacante pode fazer agora com isso",
        "amplified_risk": "string — como isso amplifica outros vetores",
        "data_at_risk": "string — qual dado/acesso está em risco"
      },
      
      "mitre_attack": {
        "tactic": "string — tática MITRE (ex: Initial Access)",
        "technique": "string — técnica (ex: Exploit Public-Facing Application)",
        "technique_id": "string — ID (ex: T1190)",
        "sub_technique_id": "string | null — sub-técnica se aplicável"
      },
      
      "exploitation": {
        "complexity": "NONE | LOW | MEDIUM | HIGH",
        "prerequisites": ["string — o que o atacante precisa antes de explorar"],
        "realistic_scenario": "string — como um atacante real usaria isso, passo a passo conciso"
      },
      
      "recommendation": {
        "priority": "IMMEDIATE | SHORT_TERM | MEDIUM_TERM | MONITOR",
        "action": "string — ação específica e técnica, não genérica",
        "verification": "string — como confirmar que a correção foi efetiva"
      }
    }
  ],

  "attack_hypotheses": [
    {
      "id": "H-001",
      "name": "string — nome descritivo do cenário",
      "threat_actor_profile": "string — quem executaria esse ataque",
      "objective": "string — o que o atacante quer alcançar",
      "prerequisites": ["string — o que o atacante já precisa ter/saber"],
      "kill_chain": [
        {
          "step": 1,
          "action": "string — ação específica",
          "mitre_ttp": "string — T1xxx.xxx",
          "tool_example": "string — ferramenta que executaria isso"
        }
      ],
      "probability": "HIGH | MEDIUM | LOW",
      "probability_justification": "string — por que essa probabilidade",
      "potential_impact": "string — impacto se executado com sucesso",
      "detection_indicators": ["string — o que um SOC veria nos logs"]
    }
  ],

  "infrastructure_intelligence": {
    "hosting_profile": {
      "hosting_type": "OWN_DC | CLOUD | SHARED | CDN_EDGE | UNKNOWN",
      "provider": "string | null",
      "cdn_detected": "boolean",
      "cdn_provider": "string | null",
      "direct_ip_exposed": "boolean",
      "direct_ip_implication": "string — o que significa ter IP direto exposto ou não"
    },
    
    "network_exposure": {
      "open_ports": [
        {
          "port": "number",
          "protocol": "TCP | UDP",
          "service": "string",
          "version": "string | null",
          "risk_assessment": "string",
          "unexpected": "boolean — esperado para esse tipo de serviço?"
        }
      ],
      "cves_detected": [
        {
          "cve_id": "string",
          "cvss": "number",
          "description": "string",
          "exploitability": "PUBLIC_EXPLOIT | NO_PUBLIC_EXPLOIT | UNKNOWN"
        }
      ]
    },
    
    "tls_analysis": {
      "certificate_issuer": "string | null",
      "certificate_expiry": "string | null",
      "wildcard_certificate": "boolean | null",
      "san_domains_found": ["string"],
      "tls_issues": ["string"]
    },
    
    "email_security": {
      "mx_provider": "string | null",
      "spf_configured": "boolean | null",
      "dmarc_configured": "boolean | null",
      "dkim_configured": "boolean | null",
      "email_spoofing_possible": "boolean",
      "spoofing_justification": "string"
    },
    
    "security_headers": {
      "present": ["string"],
      "missing": ["string"],
      "misconfigured": [
        {
          "header": "string",
          "current_value": "string",
          "issue": "string"
        }
      ],
      "combined_risk": "string — avaliação do conjunto, não item a item"
    }
  },

  "domain_intelligence": {
    "registrar": "string | null",
    "creation_date": "string | null",
    "expiration_date": "string | null",
    "days_until_expiry": "number | null",
    "expiry_risk": "boolean",
    "privacy_protected": "boolean",
    "name_servers": ["string"],
    "correlated_domains": ["string — domínios que compartilham infraestrutura"],
    "whois_anomalies": ["string — inconsistências ou dados suspeitos no WHOIS"]
  },

  "technology_fingerprint": {
    "confirmed": [
      {
        "technology": "string",
        "version": "string | null",
        "source": "string — de onde veio essa informação",
        "intelligence_value": "string — o que essa tecnologia revela para um atacante"
      }
    ],
    "inferred": ["string — tecnologias inferidas indiretamente"],
    "unknown_components": ["string — componentes não identificados que seriam relevantes"]
  },

  "reputation_analysis": {
    "virustotal_malicious": "number | null",
    "virustotal_suspicious": "number | null",
    "abuseipdb_score": "number | null",
    "abuseipdb_reports": "number | null",
    "historical_incidents": ["string — incidentes históricos relevantes se conhecidos"],
    "reputation_assessment": "string"
  },

  "blind_spots": [
    {
      "area": "string — o que não foi possível coletar",
      "reason": "string — por que não foi coletado",
      "impact_on_analysis": "string — como isso limita as conclusões",
      "collection_method": "string — como coletar esse dado na próxima iteração"
    }
  ],

  "prioritized_recommendations": [
    {
      "priority": 1,
      "timeframe": "< 24h | < 7 dias | < 30 dias | Monitorar",
      "action": "string — ação específica",
      "addresses_findings": ["F-001", "F-002"],
      "effort": "LOW | MEDIUM | HIGH",
      "impact": "CRITICAL | HIGH | MEDIUM | LOW"
    }
  ],

  "confidence_assessment": {
    "overall_confidence": "HIGH | MEDIUM | LOW",
    "data_completeness": "number 0-100 — percentual de cobertura do reconhecimento",
    "limiting_factors": ["string — o que reduz a confiança da análise"],
    "recommended_next_steps": ["string — próximas ações de reconhecimento para completar a imagem"]
  }
}
```

---

## Regras de Qualidade de Output

### findings[] — Mínimo e Máximo
- Mínimo: 3 findings para qualquer alvo com pelo menos 1 serviço exposto
- Máximo: sem limite — liste todos que forem relevantes
- PROIBIDO: findings com título genérico como "Configuração de segurança fraca" sem especificidade técnica

### attack_hypotheses[] — Obrigatório
- Mínimo: 2 hipóteses para qualquer alvo
- Hipótese 1 deve ser sempre o caminho de menor resistência (atacante oportunista)
- Hipótese 2 deve ser o cenário mais impactante (atacante motivado)
- Se dado governamental disponível: Hipótese 3 deve considerar o perfil financeiro

### Campos Proibidos de Serem Vagos
- `realistic_scenario`: deve ter sequência de passos concretos, não "poderia ser explorado"
- `action` em recommendations: deve começar com verbo imperativo + objeto específico
- `risk_justification`: deve mencionar dados concretos coletados, não afirmações genéricas

### Auto-Validação Antes de Retornar
1. O JSON é válido? (sem vírgula final, aspas corretas, colchetes fechados)
2. Todos os findings têm technique_id preenchido?
3. executive_summary.key_attack_vectors tem ao menos 2 itens?
4. blind_spots documenta o que o crt.sh não retornou, se aplicável?
5. prioritized_recommendations está ordenada por prioridade real, não arbitrária?

---

## Tratamento de Dados Insuficientes

Se um campo não pode ser preenchido por falta de dado:
- Use `null` para campos de valor único
- Use `[]` para arrays
- Use `"Não coletado — [motivo]"` para strings obrigatórias onde null não é aceito

NUNCA invente dados para preencher campos. NUNCA use "N/A" — use null ou string explicativa.