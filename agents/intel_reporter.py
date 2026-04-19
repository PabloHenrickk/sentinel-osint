"""
intel_reporter.py — Relatório de Inteligência Nível Sênior

Converte o JSON do ai_analyst em relatório Markdown estruturado no padrão
de pentest profissional. Funciona em dois modos:

  1. Integrado no pipeline — chamado automaticamente pelo main.py após ai_analyst
  2. Standalone — python agents/intel_reporter.py data/arquivo_ai_analysis.json

Estrutura do relatório gerado:
  00. Capa e metadados
  01. Sumário Executivo (risco em linguagem de negócio + ações imediatas)
  02. Threat Profile (perfil do alvo e modelagem de ameaças)
  03. Superfície de Ataque (infraestrutura, portas, serviços, headers)
  04. Findings Detalhados (cada achado com evidência, kill chain, remediação)
  05. Narrativa de Ataque (como um adversário chegaria ao objetivo)
  06. Hipóteses Adversariais (cenários com kill chain completo)
  07. Pontos Cegos da Análise (o que não foi possível verificar)
  08. Roadmap de Remediação (priorizado por risco com prazo)
  09. Apêndice Técnico (dados brutos relevantes)
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger

logger = get_logger(__name__)

REPORTS_DIR = Path("reports")

# Mapeamento de severidade para símbolos e rótulos no relatório
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH"    : "🟠",
    "MEDIUM"  : "🟡",
    "LOW"     : "🔵",
    "INFO"    : "⚪",
}

SEVERITY_PT = {
    "CRITICAL": "CRÍTICO",
    "HIGH"    : "ALTO",
    "MEDIUM"  : "MÉDIO",
    "LOW"     : "BAIXO",
    "INFO"    : "INFORMATIVO",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

PROBABILITY_PT = {
    "HIGH"  : "ALTA",
    "MEDIUM": "MÉDIA",
    "LOW"   : "BAIXA",
    "ALTA"  : "ALTA",
    "MÉDIA" : "MÉDIA",
    "BAIXA" : "BAIXA",
}

PRAZO_MAP = {
    "CRITICAL": "< 24 horas",
    "HIGH"    : "< 7 dias",
    "MEDIUM"  : "< 30 dias",
    "LOW"     : "Monitorar",
    "INFO"    : "Registrar",
}

RISK_COLOR = {
    "CRITICAL": "CRÍTICO",
    "HIGH"    : "ALTO",
    "MEDIUM"  : "MÉDIO",
    "LOW"     : "BAIXO",
    "INFO"    : "INFORMATIVO",
}


# ── Helpers ───────────────────────────────────────────────────────────────

def _sev(finding: dict) -> str:
    return finding.get("severity", "INFO").upper()


def _sev_pt(sev: str) -> str:
    return SEVERITY_PT.get(sev.upper(), sev)


def _emoji(sev: str) -> str:
    return SEVERITY_EMOJI.get(sev.upper(), "⚪")


def _prazo(sev: str) -> str:
    return PRAZO_MAP.get(sev.upper(), "Monitorar")


def _mitre_id(finding: dict) -> str:
    mitre = finding.get("mitre_attack") or {}
    if isinstance(mitre, dict):
        return mitre.get("technique_id") or finding.get("mitre_id", "—")
    return finding.get("mitre_id", "—")


def _mitre_name(finding: dict) -> str:
    mitre = finding.get("mitre_attack") or {}
    if isinstance(mitre, dict):
        return mitre.get("technique") or finding.get("mitre_name", "—")
    return finding.get("mitre_name", "—")


def _mitre_url(technique_id: str) -> str:
    if not technique_id or technique_id == "—":
        return ""
    clean = technique_id.replace(".", "/")
    return f"https://attack.mitre.org/techniques/{clean}/"


def _sorted_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(_sev(f), 4))


def _count_by_severity(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = _sev(f)
        if sev in counts:
            counts[sev] += 1
    return counts


def _risk_level(analysis: dict) -> str:
    exec_s = analysis.get("executive_summary") or {}
    if isinstance(exec_s, dict):
        return (exec_s.get("risk_level") or analysis.get("priority_level") or "INDETERMINADO").upper()
    return (analysis.get("priority_level") or "INDETERMINADO").upper()


def _hline(char: str = "─", width: int = 72) -> str:
    return char * width


# ── Seções do relatório ───────────────────────────────────────────────────

def _section_cover(analysis: dict, target: str) -> str:
    risk     = _risk_level(analysis)
    emoji    = _emoji(risk)
    analyzed = analysis.get("analyzed_at", datetime.now().isoformat())[:19].replace("T", " ")
    provider = analysis.get("provider", "—")
    model    = analysis.get("model", "—")
    findings = analysis.get("findings") or []
    counts   = _count_by_severity(findings)

    return f"""# SENTINEL OSINT — Relatório de Inteligência

**Alvo:** `{target}`
**Classificação de Risco:** {emoji} **{_sev_pt(risk)}**
**Data da Análise:** {analyzed}
**Gerado por:** Sentinel OSINT v1.0.0-dev | {provider} / {model}
**Classificação:** USO INTERNO — CONFIDENCIAL

---

## Resumo de Achados

| Severidade | Quantidade |
|:-----------|:----------:|
| 🔴 CRÍTICO  | {counts['CRITICAL']} |
| 🟠 ALTO     | {counts['HIGH']} |
| 🟡 MÉDIO    | {counts['MEDIUM']} |
| 🔵 BAIXO    | {counts['LOW']} |
| ⚪ INFO      | {counts['INFO']} |
| **TOTAL**  | **{len(findings)}** |

---
"""


def _section_executive_summary(analysis: dict) -> str:
    exec_s = analysis.get("executive_summary") or {}
    risk   = _risk_level(analysis)
    emoji  = _emoji(risk)

    if isinstance(exec_s, dict):
        justification = exec_s.get("risk_justification", "")
        actions       = exec_s.get("immediate_actions_required") or []
        vectors       = exec_s.get("key_attack_vectors") or []
    else:
        justification = str(exec_s) if exec_s else ""
        actions       = analysis.get("recommendations") or []
        vectors       = []

    lines = [
        "## 01. Sumário Executivo",
        "",
        f"**Nível de Risco Global: {emoji} {_sev_pt(risk)}**",
        "",
    ]

    if justification:
        lines += [justification, ""]

    if actions:
        lines.append("### Ações Imediatas Requeridas")
        lines.append("")
        for i, action in enumerate(actions, 1):
            lines.append(f"{i}. {action}")
        lines.append("")

    if vectors:
        lines.append("### Vetores de Ataque Identificados")
        lines.append("")
        for v in vectors:
            lines.append(f"- {v}")
        lines.append("")

    findings = analysis.get("findings") or []
    if not justification and findings:
        counts    = _count_by_severity(findings)
        criticals = [f for f in findings if _sev(f) == "CRITICAL"]
        highs     = [f for f in findings if _sev(f) == "HIGH"]

        lines.append(
            f"A análise identificou **{len(findings)} achados** de segurança, "
            f"sendo **{counts['CRITICAL']} críticos** e **{counts['HIGH']} altos**. "
        )
        if criticals:
            titles = ", ".join(f.get("title", "?") for f in criticals[:3])
            lines.append(
                f"Os achados críticos — {titles} — requerem remediação imediata "
                f"em menos de 24 horas para reduzir a exposição ao risco."
            )
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_threat_profile(analysis: dict) -> str:
    tp = analysis.get("threat_profile") or {}

    lines = [
        "## 02. Perfil de Ameaça",
        "",
        "| Dimensão | Avaliação |",
        "|:---------|:----------|",
    ]

    value        = tp.get("target_value", "—")
    value_just   = tp.get("target_value_justification", "")
    threat_actor = tp.get("primary_threat_actor", "—")
    motivation   = tp.get("threat_actor_motivation", "—")
    surface      = tp.get("attack_surface_category", "—")

    lines.append(f"| Valor para atacante | {value} — {value_just} |")
    lines.append(f"| Perfil de ameaça primário | {threat_actor} |")
    lines.append(f"| Motivação do atacante | {motivation} |")
    lines.append(f"| Superfície de ataque | {surface} |")
    lines.append("")

    if not tp:
        findings  = analysis.get("findings") or []
        criticals = [f for f in findings if _sev(f) == "CRITICAL"]
        lines.pop()
        lines = lines[:1] + [
            "",
            "> Perfil inferido a partir dos achados identificados.",
            "",
            "| Dimensão | Avaliação |",
            "|:---------|:----------|",
        ]
        if criticals:
            lines.append("| Valor para atacante | ALTO — presença de serviços críticos expostos |")
            lines.append("| Perfil de ameaça primário | Oportunista / Ransomware |")
        else:
            lines.append("| Valor para atacante | MÉDIO — superfície de reconhecimento ativa |")
            lines.append("| Perfil de ameaça primário | Oportunista |")
        lines.append("| Motivação | Acesso inicial / Reconhecimento |")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_attack_surface(analysis: dict, raw_data: dict) -> str:
    findings = analysis.get("findings") or []
    lines    = [
        "## 03. Superfície de Ataque",
        "",
    ]

    infra = analysis.get("infrastructure_intelligence") or {}
    ports = infra.get("open_ports") or []

    if not ports:
        port_findings = [f for f in findings if "porta" in f.get("title", "").lower()
                         or "port" in f.get("title", "").lower()
                         or f.get("category", "") in ("Backdoor", "Remote Access")]
        if port_findings:
            ports = [f.get("title", "") for f in port_findings]

    if ports:
        lines += ["### Portas e Serviços Expostos", ""]
        if isinstance(ports, list) and ports and isinstance(ports[0], int):
            lines.append(f"**Portas abertas:** `{', '.join(str(p) for p in ports)}`")
        elif isinstance(ports, list):
            for p in ports[:10]:
                lines.append(f"- {p}")
        lines.append("")

    header_findings = [f for f in findings if f.get("category") in
                       ("Transport Security", "Security Headers", "Information Disclosure",
                        "Session Security", "API Security")]
    if header_findings:
        lines += ["### Análise de Headers HTTP", ""]
        lines.append("| Categoria | Severidade | Finding |")
        lines.append("|:----------|:----------:|:--------|")
        for f in header_findings:
            sev   = _sev(f)
            emoji = _emoji(sev)
            title = f.get("title", "—")
            lines.append(f"| {f.get('category', '—')} | {emoji} {_sev_pt(sev)} | {title} |")
        lines.append("")

    rep = analysis.get("reputation_analysis") or {}
    if rep:
        lines += ["### Reputação e Inteligência de Ameaças", ""]
        for k, v in rep.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_findings(analysis: dict) -> str:
    findings = _sorted_findings(analysis.get("findings") or [])

    lines = [
        "## 04. Findings Detalhados",
        "",
        f"Total de achados: **{len(findings)}**",
        "",
    ]

    for idx, f in enumerate(findings, 1):
        sev      = _sev(f)
        emoji    = _emoji(sev)
        title    = f.get("title", "Sem título")
        mid      = _mitre_id(f)
        mname    = _mitre_name(f)
        murl     = _mitre_url(mid)
        prazo    = _prazo(sev)
        desc     = f.get("description") or ""
        evidence = f.get("evidence") or ""
        source   = f.get("_source", "")

        lines += [
            f"### F-{idx:03d} | {emoji} {_sev_pt(sev)} — {title}",
            "",
        ]

        mitre_cell = f"[{mid}]({murl}) — {mname}" if murl else f"{mid} — {mname}"
        lines += [
            "| Campo | Detalhe |",
            "|:------|:--------|",
            f"| **Severidade** | {emoji} {_sev_pt(sev)} |",
            f"| **MITRE ATT&CK** | {mitre_cell} |",
            f"| **Prazo de remediação** | {prazo} |",
            f"| **Categoria** | {f.get('category', '—')} |",
        ]

        cvss = f.get("cvss_estimate")
        if cvss:
            lines.append(f"| **CVSS Estimado** | {cvss} |")

        if source:
            source_label = {"header_agent": "Header Agent", "subdomain_agent": "Subdomain Agent"}.get(source, source)
            lines.append(f"| **Fonte** | {source_label} (determinístico) |")

        lines.append("")

        if desc:
            lines += ["**Descrição**", "", desc, ""]

        if evidence:
            lines += ["**Evidência**", "", f"```", evidence, "```", ""]

        tech = f.get("technical_detail") or {}
        if isinstance(tech, dict) and any(tech.values()):
            lines += ["**Detalhe Técnico**", ""]
            if tech.get("what"):   lines.append(f"- **O quê:** {tech['what']}")
            if tech.get("where"):  lines.append(f"- **Onde:** {tech['where']}")
            if tech.get("evidence") and tech["evidence"] != evidence:
                lines.append(f"- **Evidência adicional:** {tech['evidence']}")
            lines.append("")

        impact = f.get("adversarial_impact") or {}
        if isinstance(impact, dict) and any(impact.values()):
            lines += ["**Impacto Adversarial**", ""]
            if impact.get("immediate_risk"): lines.append(f"- **Risco imediato:** {impact['immediate_risk']}")
            if impact.get("amplified_risk"): lines.append(f"- **Risco ampliado:** {impact['amplified_risk']}")
            if impact.get("data_at_risk"):   lines.append(f"- **Dados em risco:** {impact['data_at_risk']}")
            lines.append("")

        exploit = f.get("exploitation") or {}
        if isinstance(exploit, dict):
            complexity = exploit.get("complexity", "")
            scenario   = exploit.get("realistic_scenario", "")
            prereqs    = exploit.get("prerequisites") or []

            if complexity or scenario:
                lines += ["**Cenário de Exploração**", ""]
                if complexity:
                    lines.append(f"- **Complexidade:** {complexity}")
                if prereqs:
                    lines.append(f"- **Pré-requisitos:** {', '.join(prereqs)}")
                if scenario:
                    lines.append("")
                    steps = [s.strip() for s in scenario.split(". ") if s.strip()]
                    if len(steps) > 1:
                        for step in steps:
                            if not step.endswith("."):
                                step += "."
                            lines.append(f"> {step}")
                    else:
                        lines.append(f"> {scenario}")
                lines.append("")

        rec = f.get("recommendation") or {}
        if isinstance(rec, dict) and any(rec.values()):
            lines += ["**Remediação**", ""]
            if rec.get("action"):
                lines.append(f"**Ação:** {rec['action']}")
            if rec.get("verification"):
                lines.append(f"")
                lines.append(f"**Verificação:**")
                lines.append(f"```bash")
                lines.append(rec["verification"])
                lines.append(f"```")
            lines.append("")

        lines.append(_hline("─", 60))
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_attack_narrative(analysis: dict, target: str) -> str:
    findings  = _sorted_findings(analysis.get("findings") or [])
    criticals = [f for f in findings if _sev(f) == "CRITICAL"]
    highs     = [f for f in findings if _sev(f) == "HIGH"]
    mediums   = [f for f in findings if _sev(f) == "MEDIUM"]

    lines = [
        "## 05. Narrativa de Ataque",
        "",
        "> *Esta seção descreve o caminho mais provável que um atacante real "
        "percorreria usando exclusivamente os dados coletados por fontes abertas. "
        "Nenhuma interação ativa com o alvo foi realizada.*",
        "",
        "### Fase 1 — Reconhecimento Passivo",
        "",
        f"O alvo `{target}` foi identificado através de fontes abertas públicas. "
        "O reconhecimento inicial revelou a seguinte superfície de ataque:",
        "",
    ]

    infra_findings = [f for f in findings if f.get("category") in
                      ("Remote Access", "Database", "Backdoor", "Non-Standard Port")]
    if infra_findings:
        for f in infra_findings[:5]:
            lines.append(f"- {f.get('title', '—')} ({_emoji(_sev(f))} {_sev_pt(_sev(f))})")
        lines.append("")

    header_findings = [f for f in findings if f.get("category") in
                       ("Transport Security", "Security Headers", "Information Disclosure")]
    if header_findings:
        lines.append("A análise de headers HTTP complementou o perfil de exposição:")
        for f in header_findings[:3]:
            lines.append(f"- {f.get('title', '—')}")
        lines.append("")

    lines += [
        "### Fase 2 — Análise e Priorização",
        "",
    ]

    if criticals:
        lines.append(
            "Com os dados em mãos, um atacante priorizaria os vetores críticos. "
            f"O achado de maior valor imediato é **{criticals[0].get('title', '—')}** — "
            "exploitável sem autenticação, com impacto direto no sistema."
        )
        lines.append("")

        exploit  = criticals[0].get("exploitation") or {}
        scenario = exploit.get("realistic_scenario", "")
        if scenario:
            lines.append("O caminho de exploração mais direto:")
            lines.append("")
            steps = [s.strip() for s in scenario.split(". ") if s.strip()]
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

    lines += [
        "### Fase 3 — Amplificação",
        "",
    ]

    if highs:
        lines.append(
            "Após o acesso inicial, os achados de severidade alta serviriam "
            "para ampliar o controle ou garantir persistência:"
        )
        lines.append("")
        for f in highs[:3]:
            lines.append(f"- **{f.get('title') or '—'}:** {(f.get('description') or '')[:120]}...")
        lines.append("")

    if mediums:
        lines += [
            "### Fase 4 — Reconhecimento Interno",
            "",
            "Os achados de severidade média fornecem inteligência adicional "
            "que um atacante persistente usaria para expandir o acesso:",
            "",
        ]
        for f in mediums[:3]:
            lines.append(f"- {f.get('title', '—')}")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_hypotheses(analysis: dict) -> str:
    hypotheses = analysis.get("attack_hypotheses") or []

    lines = [
        "## 06. Hipóteses Adversariais",
        "",
    ]

    if not hypotheses:
        lines += ["> Nenhuma hipótese adversarial gerada pelo modelo.", "", "---"]
        return "\n".join(lines)

    for idx, h in enumerate(hypotheses, 1):
        if not isinstance(h, dict):
            continue

        name      = h.get("name", f"Hipótese {idx}")
        actor     = h.get("threat_actor_profile", "—")
        objective = h.get("objective", "—")
        prob      = PROBABILITY_PT.get(h.get("probability", "").upper(), h.get("probability", "—"))
        prob_just = h.get("probability_justification", "")
        prereqs   = h.get("prerequisites") or []
        impact    = h.get("potential_impact", "")
        detection = h.get("detection_indicators") or []
        kill      = h.get("kill_chain") or []

        prob_emoji = {"ALTA": "🔴", "MÉDIA": "🟡", "BAIXA": "🔵"}.get(prob, "⚪")

        lines += [
            f"### H-{idx:03d} | {name}",
            "",
            f"| Campo | Detalhe |",
            f"|:------|:--------|",
            f"| **Probabilidade** | {prob_emoji} {prob} |",
            f"| **Threat Actor** | {actor} |",
            f"| **Objetivo** | {objective} |",
        ]

        if impact:
            lines.append(f"| **Impacto potencial** | {impact} |")

        lines.append("")

        if prob_just:
            lines += [f"**Justificativa:** {prob_just}", ""]

        if prereqs:
            lines += ["**Pré-requisitos:**", ""]
            for p in prereqs:
                lines.append(f"- {p}")
            lines.append("")

        if kill:
            lines += ["**Kill Chain:**", ""]
            for step in kill:
                if isinstance(step, dict):
                    num    = step.get("step", "?")
                    action = step.get("action", "")
                    ttp    = step.get("mitre_ttp", "")
                    tool   = step.get("tool_example", "")
                    step_line = f"{num}. {action}"
                    if ttp:
                        step_line += f" `[{ttp}]`"
                    lines.append(step_line)
                    if tool:
                        lines.append(f"   - *Ferramenta: `{tool}`*")
                else:
                    lines.append(f"- {step}")
            lines.append("")

        if detection:
            lines += ["**Indicadores de Detecção (SOC):**", ""]
            for d in detection:
                lines.append(f"- {d}")
            lines.append("")

        lines.append(_hline("─", 60))
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_blind_spots(analysis: dict) -> str:
    blind_spots = analysis.get("blind_spots") or []

    lines = [
        "## 07. Pontos Cegos da Análise",
        "",
        "> *Limitações inerentes ao reconhecimento passivo. "
        "Estes pontos devem ser investigados em um engagement de pentest ativo.*",
        "",
    ]

    if not blind_spots:
        lines += [
            "| Área | Motivo | Impacto | Como coletar |",
            "|:-----|:-------|:--------|:-------------|",
            "| Autenticação interna | OSINT passivo não acessa recursos autenticados | Potenciais vulnerabilidades internas não mapeadas | Pentest ativo com credenciais |",
            "| Configuração de WAF | Não detectável via headers públicos | Bypass pode ser mais fácil do que aparenta | Teste ativo de payloads |",
            "| Versões internas de software | Banners podem estar ocultados | CVEs não mapeados | Scan autenticado |",
            "",
        ]
    else:
        lines += [
            "| Área | Motivo | Impacto na Análise | Como coletar |",
            "|:-----|:-------|:-------------------|:-------------|",
        ]
        for bs in blind_spots:
            if isinstance(bs, dict):
                area   = bs.get("area", "—")
                reason = bs.get("reason", "—")
                impact = bs.get("impact_on_analysis", "—")
                method = bs.get("collection_method", "—")
                lines.append(f"| {area} | {reason} | {impact} | {method} |")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_remediation_roadmap(analysis: dict) -> str:
    findings = _sorted_findings(analysis.get("findings") or [])
    recs_llm = analysis.get("prioritized_recommendations") or \
               analysis.get("recommendations") or []

    lines = [
        "## 08. Roadmap de Remediação",
        "",
        "Ações ordenadas por severidade e prazo. "
        "Cada item inclui verificação para confirmar a remediação.",
        "",
        "| # | Prioridade | Finding | Prazo | Ação |",
        "|:--|:----------:|:--------|:------|:-----|",
    ]

    for idx, f in enumerate(findings, 1):
        sev   = _sev(f)
        emoji = _emoji(sev)
        title = f.get("title", "—")
        prazo = _prazo(sev)
        rec   = f.get("recommendation") or {}
        action = ""
        if isinstance(rec, dict):
            action = rec.get("action", "—")
        elif isinstance(rec, str):
            action = rec
        action_short = action[:80] + "..." if len(action) > 80 else action
        lines.append(f"| {idx} | {emoji} {_sev_pt(sev)} | {title} | {prazo} | {action_short} |")

    lines.append("")

    critical_high = [f for f in findings if _sev(f) in ("CRITICAL", "HIGH")]
    if critical_high:
        lines += [
            "### Verificações de Remediação — Críticos e Altos",
            "",
        ]
        for f in critical_high:
            rec = f.get("recommendation") or {}
            if isinstance(rec, dict) and rec.get("verification"):
                lines.append(f"**{f.get('title', '—')}**")
                lines.append(f"```bash")
                lines.append(rec["verification"])
                lines.append(f"```")
                lines.append("")

    if recs_llm:
        lines += ["### Recomendações Adicionais", ""]
        for r in recs_llm[:10]:
            if isinstance(r, dict):
                action = r.get("action", "") or r.get("recommendation", "") or str(r)
            else:
                action = str(r)
            if action:
                lines.append(f"- {action}")
        lines.append("")

    lines.append("---")
    return "\n".join(lines)


def _section_appendix(analysis: dict, target: str) -> str:
    lines = [
        "## 09. Apêndice Técnico",
        "",
        "### Metadados da Análise",
        "",
        f"| Campo | Valor |",
        f"|:------|:------|",
        f"| Alvo | `{target}` |",
        f"| Provider IA | {analysis.get('provider', '—')} |",
        f"| Modelo | {analysis.get('model', '—')} |",
        f"| Análise em | {(analysis.get('analyzed_at') or '—')[:19]} |",
        f"| Arquivo JSON | `{analysis.get('saved_to', '—')}` |",
        f"| Confidence Score | {analysis.get('confidence_score', '—')} |",
        "",
    ]

    conf = analysis.get("confidence_assessment") or {}
    if isinstance(conf, dict) and conf:
        lines += ["### Avaliação de Confiança", ""]
        for k, v in conf.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    warnings = analysis.get("_validation_warnings") or []
    if warnings:
        lines += [
            "### Avisos de Validação do Schema",
            "",
            "> Os seguintes campos do JSON do modelo não corresponderam ao schema esperado:",
            "",
        ]
        for w in warnings[:5]:
            lines.append(f"- `{w}`")
        lines.append("")

    lines += [
        "### Fontes de Dados Utilizadas",
        "",
        "| Fonte | Tipo | Dados Coletados |",
        "|:------|:-----|:----------------|",
        "| WHOIS | Registro público | Registrar, datas, name servers |",
        "| DNS | Infraestrutura pública | Registros A, MX, TXT, NS, CNAME |",
        "| Shodan InternetDB | Indexação pública | Portas, serviços, CVEs |",
        "| Certificate Transparency (crt.sh) | Logs públicos | Subdomínios, certificados |",
        "| VirusTotal | Reputação pública | Classificação de domínio/IP |",
        "| AbuseIPDB | Reputação pública | Score de abuso de IP |",
        "| HTTP Headers | Requisição direta | Headers de segurança e info leakage |",
        "",
        "### Disclaimer Legal",
        "",
        "> Esta análise foi conduzida exclusivamente com dados públicos e fontes abertas (OSINT). "
        "Nenhuma interação ativa com sistemas do alvo foi realizada. "
        "O uso destas informações para fins maliciosos é tipificado como crime pela Lei 12.737/2012 (Brasil). "
        "Este relatório destina-se exclusivamente a fins defensivos e educacionais.",
        "",
    ]

    return "\n".join(lines)


# ── Entry point ───────────────────────────────────────────────────────────

def run(
    analysis     : dict,
    raw_data     : Optional[dict] = None,
    output_path  : Optional[str]  = None,
) -> str:
    """
    Gera relatório Markdown a partir do JSON do ai_analyst.

    Args:
        analysis    : dict retornado pelo ai_analyst.run()
        raw_data    : dados brutos opcionais (collected_data, shodan, etc.)
        output_path : caminho explícito para salvar. Se None, salva em reports/

    Returns:
        Caminho do arquivo gerado.
    """
    target = analysis.get("target", "desconhecido")
    logger.info(f"[intel_reporter] Gerando relatório para: {target}")

    raw_data = raw_data or {}

    sections = [
        _section_cover(analysis, target),
        _section_executive_summary(analysis),
        _section_threat_profile(analysis),
        _section_attack_surface(analysis, raw_data),
        _section_findings(analysis),
        _section_attack_narrative(analysis, target),
        _section_hypotheses(analysis),
        _section_blind_spots(analysis),
        _section_remediation_roadmap(analysis),
        _section_appendix(analysis, target),
    ]

    report_md = "\n\n".join(sections)

    if output_path:
        path = Path(output_path)
    else:
        REPORTS_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = target.replace(".", "_").replace("/", "-").replace(":", "-")
        path = REPORTS_DIR / f"{safe_name}_{timestamp}_intel_report.md"

    path.write_text(report_md, encoding="utf-8")
    logger.info(f"[intel_reporter] Relatório salvo: {path}")

    return str(path)


# ── Standalone CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Sentinel OSINT — Intel Reporter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python agents/intel_reporter.py data/scanme_nmap_org_20260411_163043_ai_analysis.json
  python agents/intel_reporter.py data/arquivo.json --output reports/meu_relatorio.md
        """,
    )
    parser.add_argument("json_file",  help="Caminho para o arquivo JSON do ai_analyst")
    parser.add_argument("--output",   help="Caminho de saída do relatório MD (opcional)", default=None)
    parser.add_argument("--verbose",  action="store_true", help="Log detalhado")

    args = parser.parse_args()

    import logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s | %(message)s")

    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"Erro: arquivo não encontrado: {json_path}")
        sys.exit(1)

    try:
        analysis = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Erro ao ler JSON: {e}")
        sys.exit(1)

    report_path = run(analysis=analysis, output_path=args.output)

    print(f"\n{'='*60}")
    print(f"INTEL REPORTER — {analysis.get('target', '?')}")
    print(f"{'='*60}")
    print(f"Relatório gerado: {report_path}")

    findings = analysis.get("findings") or []
    counts   = _count_by_severity(findings)
    print(f"\nAchados: {len(findings)} total")
    for sev, count in counts.items():
        if count > 0:
            print(f"  {_emoji(sev)} {_sev_pt(sev)}: {count}")

    print(f"\nAbra o relatório:")
    print(f"  {report_path}")