"""
core/graph.py — Intelligence Graph Engine

Constrói um grafo dirigido em memória com NetworkX a partir das entidades
coletadas pelos providers. Calcula score de risco agregado por nó e exporta
para o ai_analyst como dict estruturado.

Estrutura do grafo:
  Nós   → empresa, domínio, ip, sócio, ASN, CIDR, órgão público
  Arestas → relações tipadas: tem_dominio, resolve_para, tem_socio,
             pertence_a_asn, anuncia_cidr, tem_contrato_com,
             compartilha_ip_com

Por que NetworkX e não um grafo manual:
  - Algoritmos prontos: shortest_path, neighbors, degree centrality
  - Exportação nativa para dict/JSON
  - Detecção de comunidades (Fase 4)
  - Custo: ~2MB de RAM para grafos de até 10k nós

Dependências:
  pip install networkx
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from providers.base import NormalizedEntity, ProviderResult

logger = logging.getLogger(__name__)


# ── Tipos de nó e aresta ──────────────────────────────────────────────────────

# Todos os tipos de nó possíveis no grafo
NODE_TYPES = {
    "empresa",        # CNPJ
    "dominio",        # domínio alvo
    "ip",             # endereço IPv4
    "socio",          # sócio/administrador (QSA)
    "asn",            # Autonomous System Number
    "cidr_block",     # prefixo CIDR da organização
    "orgao_publico",  # órgão contratante (gov_provider)
    "subdomain",      # subdomínio descoberto
    "neighbor",       # domínio vizinho (reverse IP)
    "cve",            # vulnerabilidade detectada
}

# Pesos de risco base por tipo de nó
# Quanto maior, mais o nó contribui para o risk score agregado
NODE_RISK_WEIGHTS: dict[str, float] = {
    "empresa":       0.0,   # neutro — risco vem dos atributos
    "dominio":       5.0,
    "ip":            10.0,
    "socio":         0.0,
    "asn":           0.0,
    "cidr_block":    0.0,
    "orgao_publico": 0.0,
    "subdomain":     8.0,
    "neighbor":      3.0,
    "cve":           25.0,  # CVE detectado = risco alto por padrão
}

# Portas que elevam risco quando abertas
RISKY_PORTS: set[int] = {
    21,    # FTP — transferência sem criptografia
    23,    # Telnet — autenticação em plaintext
    445,   # SMB — alvo frequente de ransomware
    1433,  # MSSQL exposto
    3306,  # MySQL exposto
    3389,  # RDP — brute force e exploits frequentes
    5432,  # PostgreSQL exposto
    5900,  # VNC — acesso remoto sem MFA
    6379,  # Redis sem autenticação
    27017, # MongoDB sem autenticação
    9200,  # Elasticsearch exposto
}


# ── Dataclass de resultado ────────────────────────────────────────────────────

@dataclass
class GraphResult:
    """
    Output do grafo para o ai_analyst.
    Tudo serializado — sem objetos NetworkX no output.
    """
    nodes:           list[dict]        # todos os nós com atributos e risk_score
    edges:           list[dict]        # todas as arestas com tipo e peso
    risk_summary:    dict[str, Any]    # score agregado + breakdown por categoria
    high_risk_nodes: list[dict]        # nós com risk_score > threshold
    correlations:    list[dict]        # conexões entre entidades de providers diferentes
    stats:           dict[str, int]    # contagens gerais

    def to_dict(self) -> dict:
        """Serialização limpa para JSON / ai_analyst."""
        return {
            "nodes":           self.nodes,
            "edges":           self.edges,
            "risk_summary":    self.risk_summary,
            "high_risk_nodes": self.high_risk_nodes,
            "correlations":    self.correlations,
            "stats":           self.stats,
        }


# ── Graph Engine ──────────────────────────────────────────────────────────────

class SentinelGraph:
    """
    Motor de grafo do Sentinel OSINT.

    Uso típico:
        graph = SentinelGraph()
        graph.ingest(provider_results)  # lista de ProviderResult
        result = graph.compute()        # GraphResult pronto para o ai_analyst
    """

    def __init__(self) -> None:
        # DiGraph: arestas têm direção (empresa → domínio, não o contrário)
        self._g: nx.DiGraph = nx.DiGraph()
        self._entity_index: dict[str, list[NormalizedEntity]] = {}

    # ── Ingestão de entidades ─────────────────────────────────────────────────

    def ingest(self, results: list[ProviderResult]) -> None:
        """
        Recebe lista de ProviderResult e constrói o grafo.
        Cada NormalizedEntity vira um ou dois nós + uma aresta.
        """
        for result in results:
            for entity in result.entities:
                self._process_entity(entity)
                # Indexa por tipo para consultas rápidas depois
                self._entity_index.setdefault(entity.data_type, []).append(entity)

        logger.info(
            "SentinelGraph: %d nós, %d arestas após ingestão",
            self._g.number_of_nodes(),
            self._g.number_of_edges(),
        )

    def _process_entity(self, entity: NormalizedEntity) -> None:
        """
        Roteador principal: decide como cada data_type vira nós e arestas.
        Novos data_types adicionados em providers precisam de um case aqui.
        """
        dt = entity.data_type

        # ── CNPJ / empresa ────────────────────────────────────────────────────
        if dt == "empresa":
            self._add_node(entity.entity, "empresa", {
                "nome":     entity.metadata.get("nome", ""),
                "situacao": entity.metadata.get("situacao", ""),
                "uf":       entity.metadata.get("uf", ""),
                "cnae":     entity.metadata.get("cnae_principal", ""),
                "confidence": entity.confidence,
            })

        # ── Sócio (QSA) ───────────────────────────────────────────────────────
        elif dt == "socio":
            socio_id = f"socio:{entity.value}"
            self._add_node(socio_id, "socio", {
                "nome":           entity.value,
                "qualificacao":   entity.metadata.get("qualificacao", ""),
                "data_entrada":   entity.metadata.get("data_entrada", ""),
                "confidence":     entity.confidence,
            })
            # Aresta: empresa → tem_socio → sócio
            self._add_edge(entity.entity, socio_id, "tem_socio", weight=1.0)

        # ── Contrato público ──────────────────────────────────────────────────
        elif dt == "contrato_publico":
            orgao = entity.metadata.get("orgao", "orgao_desconhecido")
            orgao_id = f"orgao:{orgao}"
            self._add_node(orgao_id, "orgao_publico", {
                "nome":       orgao,
                "confidence": entity.confidence,
            })
            self._add_edge(
                entity.entity, orgao_id, "tem_contrato_com",
                weight=0.5,
                metadata={
                    "numero":  entity.value,
                    "valor":   entity.metadata.get("valor_brl", 0),
                    "vigencia": entity.metadata.get("vigencia", ""),
                }
            )

        # ── Sanção (CEIS / CNEP) ──────────────────────────────────────────────
        elif dt in ("sancao_ceis", "sancao_cnep"):
            # Sanção não cria nó novo — marca o nó da empresa como sancionada
            if self._g.has_node(entity.entity):
                self._g.nodes[entity.entity]["tem_sancao"] = True
                self._g.nodes[entity.entity]["tipo_sancao"] = dt
            # Mesmo que o nó ainda não exista, registra para quando for criado
            self._add_node(entity.entity, "empresa", {
                "tem_sancao": True,
                "tipo_sancao": dt,
            })

        # ── Portas abertas (Shodan) ───────────────────────────────────────────
        elif dt == "open_ports":
            ip_id = f"ip:{entity.entity}"
            ports_raw = entity.value  # "80,443,22,3389"
            ports = [int(p) for p in ports_raw.split(",") if p.isdigit()]
            risky = [p for p in ports if p in RISKY_PORTS]

            self._add_node(ip_id, "ip", {
                "ports":        ports,
                "risky_ports":  risky,
                "tags":         entity.metadata.get("tags", []),
                "confidence":   entity.confidence,
            })

        # ── CVE ───────────────────────────────────────────────────────────────
        elif dt == "cve":
            ip_id  = f"ip:{entity.entity}"
            cve_id = f"cve:{entity.value}"

            self._add_node(cve_id, "cve", {
                "cve_id":     entity.value,
                "detected_by": entity.metadata.get("detected_by", ""),
                "confidence":  entity.confidence,
            })
            self._add_edge(ip_id, cve_id, "tem_vulnerabilidade", weight=2.0)

        # ── Hostname reverso ──────────────────────────────────────────────────
        elif dt == "hostname_reverso":
            ip_id     = f"ip:{entity.entity}"
            domain_id = f"dominio:{entity.value}"
            self._add_node(domain_id, "dominio", {"confidence": entity.confidence})
            self._add_edge(domain_id, ip_id, "resolve_para", weight=1.0)

        # ── ASN ───────────────────────────────────────────────────────────────
        elif dt == "asn":
            ip_id  = f"ip:{entity.entity}"
            asn_id = f"asn:{entity.value}"
            self._add_node(asn_id, "asn", {
                "org_name":  entity.metadata.get("org_name", ""),
                "country":   entity.metadata.get("country", ""),
                "confidence": entity.confidence,
            })
            self._add_edge(ip_id, asn_id, "pertence_a_asn", weight=0.5)

        # ── CIDR block ────────────────────────────────────────────────────────
        elif dt == "cidr_block":
            asn_id  = f"asn:{entity.entity}"
            cidr_id = f"cidr:{entity.value}"
            self._add_node(cidr_id, "cidr_block", {
                "prefix":    entity.value,
                "name":      entity.metadata.get("name", ""),
                "confidence": entity.confidence,
            })
            self._add_edge(asn_id, cidr_id, "anuncia_cidr", weight=0.3)

        # ── Contexto de privacidade (VPN/hosting) ─────────────────────────────
        elif dt == "ip_privacy_context":
            ip_id = f"ip:{entity.entity}"
            # Enriquece o nó IP existente com flags de contexto
            if self._g.has_node(ip_id):
                self._g.nodes[ip_id].update({
                    "is_vpn":     entity.metadata.get("vpn", False),
                    "is_hosting": entity.metadata.get("hosting", False),
                    "is_tor":     entity.metadata.get("tor", False),
                    "is_proxy":   entity.metadata.get("proxy", False),
                })

        # ── Subdomínio (crt.sh) ───────────────────────────────────────────────
        elif dt == "subdomain":
            parent_id = f"dominio:{entity.entity}"
            sub_id    = f"subdomain:{entity.value}"
            self._add_node(sub_id, "subdomain", {
                "fqdn":       entity.value,
                "parent":     entity.entity,
                "confidence": entity.confidence,
            })
            self._add_edge(parent_id, sub_id, "tem_subdominio", weight=0.8)

        # ── Neighbor domain (reverse IP) ──────────────────────────────────────
        elif dt == "neighbor_domain":
            ip_id      = f"ip:{entity.entity}"
            neighbor_id = f"neighbor:{entity.value}"
            self._add_node(neighbor_id, "neighbor", {
                "domain":      entity.value,
                "shared_ip":   entity.metadata.get("shared_ip", ""),
                "confidence":  entity.confidence,
            })
            self._add_edge(ip_id, neighbor_id, "compartilha_ip_com", weight=1.5)

        # ── Reputação AbuseIPDB ───────────────────────────────────────────────
        elif dt == "ip_reputation":
            ip_id = f"ip:{entity.entity}"
            score = int(entity.value)
            if self._g.has_node(ip_id):
                self._g.nodes[ip_id].update({
                    "abuse_score":    score,
                    "total_reports":  entity.metadata.get("total_reports", 0),
                    "activity_types": entity.metadata.get("activity_types", []),
                    "is_tor":         entity.metadata.get("is_tor", False),
                })
            else:
                self._add_node(ip_id, "ip", {
                    "abuse_score":   score,
                    "total_reports": entity.metadata.get("total_reports", 0),
                    "confidence":    entity.confidence,
                })

        # ── Reputação VirusTotal ──────────────────────────────────────────────
        elif dt == "vt_reputation":
            node_id = f"ip:{entity.entity}" if "." not in entity.entity.replace(".", "", 3) else f"dominio:{entity.entity}"
            malicious = int(entity.value)
            if self._g.has_node(node_id):
                self._g.nodes[node_id].update({
                    "vt_malicious":  malicious,
                    "vt_suspicious": entity.metadata.get("suspicious", 0),
                    "vt_categories": entity.metadata.get("categories", []),
                })

        # ── DNS records ───────────────────────────────────────────────────────
        elif dt.startswith("dns_"):
            domain_id = f"dominio:{entity.entity}"
            self._add_node(domain_id, "dominio", {"confidence": entity.confidence})
            record_type = dt.replace("dns_", "").upper()

            if record_type == "A":
                for ip_addr in entity.metadata.get("records", []):
                    ip_id = f"ip:{ip_addr}"
                    self._add_node(ip_id, "ip", {})
                    self._add_edge(domain_id, ip_id, "resolve_para", weight=1.0)

        # ── Tipos não mapeados — logados para não perder dado ─────────────────
        else:
            logger.debug(
                "SentinelGraph: data_type '%s' não mapeado — entidade ignorada", dt
            )

    # ── Helpers de grafo ──────────────────────────────────────────────────────

    def _add_node(self, node_id: str, node_type: str, attrs: dict) -> None:
        """
        Adiciona ou atualiza nó.
        Se o nó já existe, faz merge dos atributos (não sobrescreve).
        Isso é importante: dois providers podem enriquecer o mesmo nó IP.
        """
        if self._g.has_node(node_id):
            # Merge: mantém valores existentes, adiciona novos
            existing = self._g.nodes[node_id]
            merged = {**attrs, **existing}  # existing tem prioridade
            self._g.nodes[node_id].update(merged)
        else:
            self._g.add_node(node_id, node_type=node_type, **attrs)

    def _add_edge(
        self,
        src: str,
        dst: str,
        relation: str,
        weight: float = 1.0,
        metadata: dict | None = None,
    ) -> None:
        """
        Adiciona aresta tipada entre dois nós.
        Garante que ambos os nós existam antes de criar a aresta.
        """
        if not self._g.has_node(src):
            self._g.add_node(src, node_type="unknown")
        if not self._g.has_node(dst):
            self._g.add_node(dst, node_type="unknown")

        self._g.add_edge(src, dst, relation=relation, weight=weight, **(metadata or {}))

    # ── Cálculo de risk score ─────────────────────────────────────────────────

    def _compute_node_risk(self, node_id: str) -> float:
        """
        Calcula risk score para um nó específico.

        Fórmula:
          base  = peso do tipo do nó
          + abuse_score  / 10      (0–10 pontos)
          + CVEs × 25              (cada CVE = 25 pontos)
          + risky_ports × 8        (cada porta arriscada = 8 pontos)
          + sanção ativa × 40      (CEIS/CNEP = risco corporativo alto)
          + VPN/Tor × 15           (infraestrutura de anonimização)
          + vt_malicious × 5       (cada detecção VT = 5 pontos)

        Score é clampeado em 100.
        """
        attrs     = self._g.nodes[node_id]
        node_type = attrs.get("node_type", "unknown")
        score     = NODE_RISK_WEIGHTS.get(node_type, 0.0)

        # AbuseIPDB
        abuse = attrs.get("abuse_score", 0)
        score += abuse / 10

        # Portas arriscadas
        risky_ports = attrs.get("risky_ports", [])
        score += len(risky_ports) * 8

        # Sanção corporativa
        if attrs.get("tem_sancao", False):
            score += 40

        # Anonimização (VPN, Tor, proxy)
        if attrs.get("is_tor", False):
            score += 15
        if attrs.get("is_vpn", False):
            score += 10

        # VirusTotal
        vt_malicious = attrs.get("vt_malicious", 0)
        score += vt_malicious * 5

        # CVEs herdados via arestas (nós filhos do tipo "cve")
        cve_neighbors = [
            n for n in self._g.successors(node_id)
            if self._g.nodes[n].get("node_type") == "cve"
        ]
        score += len(cve_neighbors) * 25

        return min(round(score, 2), 100.0)

    # ── Correlações entre providers ───────────────────────────────────────────

    def _find_correlations(self) -> list[dict]:
        """
        Identifica conexões entre entidades de providers diferentes.
        Exemplo: mesmo IP aparece no Shodan E no AbuseIPDB com score > 50
                 → correlação de infraestrutura de alto risco confirmada.

        Retorna lista de correlações ordenadas por score descendente.
        """
        correlations: list[dict] = []

        # Correlação 1: IPs compartilhados entre domínios diferentes
        ip_nodes = [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") == "ip"
        ]

        for ip_node in ip_nodes:
            # Predecessores = domínios que apontam para este IP
            predecessors = [
                n for n in self._g.predecessors(ip_node)
                if self._g.nodes[n].get("node_type") in ("dominio", "subdomain", "neighbor")
            ]
            if len(predecessors) > 1:
                correlations.append({
                    "type":     "shared_infrastructure",
                    "ip":       ip_node,
                    "domains":  predecessors,
                    "count":    len(predecessors),
                    "score":    min(len(predecessors) * 15, 100),
                    "finding":  f"IP {ip_node} compartilhado por {len(predecessors)} domínios",
                })

        # Correlação 2: Sócios em comum entre empresas (requer múltiplos CNPJs)
        socio_nodes = [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") == "socio"
        ]
        for socio in socio_nodes:
            empresas = list(self._g.predecessors(socio))
            if len(empresas) > 1:
                correlations.append({
                    "type":    "shared_socio",
                    "socio":   self._g.nodes[socio].get("nome", socio),
                    "empresas": empresas,
                    "score":   min(len(empresas) * 20, 100),
                    "finding": f"Sócio presente em {len(empresas)} empresas",
                })

        # Correlação 3: ASN compartilhado (mesma infraestrutura de rede)
        asn_nodes = [
            n for n, d in self._g.nodes(data=True)
            if d.get("node_type") == "asn"
        ]
        for asn in asn_nodes:
            ips = list(self._g.predecessors(asn))
            if len(ips) > 1:
                org = self._g.nodes[asn].get("org_name", asn)
                correlations.append({
                    "type":    "shared_asn",
                    "asn":     asn,
                    "org":     org,
                    "ips":     ips,
                    "score":   min(len(ips) * 10, 100),
                    "finding": f"{len(ips)} IPs na mesma organização: {org}",
                })

        return sorted(correlations, key=lambda x: x["score"], reverse=True)

    # ── Compute — entry point principal ──────────────────────────────────────

    def compute(self, risk_threshold: float = 30.0) -> GraphResult:
        """
        Executa cálculo completo: risk scores + correlações + serialização.

        Args:
            risk_threshold: Nós acima deste score vão para high_risk_nodes.
                           Default 30 — conservador, melhor false positive
                           que falso negativo em inteligência.

        Returns:
            GraphResult pronto para serialização e envio ao ai_analyst.
        """
        # ── Risk score por nó ─────────────────────────────────────────────────
        nodes_output: list[dict] = []
        total_risk   = 0.0
        risk_by_type: dict[str, float] = {}

        for node_id, attrs in self._g.nodes(data=True):
            risk = self._compute_node_risk(node_id)
            node_type = attrs.get("node_type", "unknown")

            node_dict = {
                "id":         node_id,
                "type":       node_type,
                "risk_score": risk,
                **{k: v for k, v in attrs.items() if k != "node_type"},
            }
            nodes_output.append(node_dict)

            total_risk += risk
            risk_by_type[node_type] = risk_by_type.get(node_type, 0.0) + risk

        # ── Arestas ───────────────────────────────────────────────────────────
        edges_output: list[dict] = [
            {
                "source":   src,
                "target":   dst,
                "relation": data.get("relation", ""),
                "weight":   data.get("weight", 1.0),
            }
            for src, dst, data in self._g.edges(data=True)
        ]

        # ── High risk nodes ───────────────────────────────────────────────────
        high_risk = [n for n in nodes_output if n["risk_score"] >= risk_threshold]
        high_risk.sort(key=lambda x: x["risk_score"], reverse=True)

        # ── Correlações ───────────────────────────────────────────────────────
        correlations = self._find_correlations()

        # ── Risk summary ──────────────────────────────────────────────────────
        node_count = self._g.number_of_nodes()
        avg_risk   = round(total_risk / node_count, 2) if node_count > 0 else 0.0

        risk_summary = {
            "total_risk_score": round(total_risk, 2),
            "average_node_risk": avg_risk,
            "max_node_risk":    max((n["risk_score"] for n in nodes_output), default=0.0),
            "high_risk_count":  len(high_risk),
            "risk_by_type":     {k: round(v, 2) for k, v in risk_by_type.items()},
            "has_sanctioned_entity": any(
                n.get("tem_sancao") for _, n in self._g.nodes(data=True)
            ),
            "has_cves": any(
                d.get("node_type") == "cve"
                for _, d in self._g.nodes(data=True)
            ),
            "has_high_abuse_ip": any(
                d.get("abuse_score", 0) > 50
                for _, d in self._g.nodes(data=True)
            ),
        }

        # ── Stats gerais ──────────────────────────────────────────────────────
        stats = {
            "total_nodes":    node_count,
            "total_edges":    self._g.number_of_edges(),
            "correlations":   len(correlations),
            "high_risk_nodes": len(high_risk),
            **{
                f"nodes_{ntype}": sum(
                    1 for _, d in self._g.nodes(data=True)
                    if d.get("node_type") == ntype
                )
                for ntype in NODE_TYPES
            },
        }

        logger.info(
            "SentinelGraph.compute(): %d nós, %d arestas, risk=%.1f, high_risk=%d",
            node_count,
            self._g.number_of_edges(),
            total_risk,
            len(high_risk),
        )

        return GraphResult(
            nodes=nodes_output,
            edges=edges_output,
            risk_summary=risk_summary,
            high_risk_nodes=high_risk,
            correlations=correlations,
            stats=stats,
        )

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self, path: str | Path) -> None:
        """
        Salva o grafo completo em JSON para visualização futura
        (D3.js, Gephi, etc.). Não é o output do ai_analyst — é para debug
        e para o dashboard da Fase 4.
        """
        result = self.compute()
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2, default=str)

        logger.info("Grafo exportado para %s", output_path)