"""Attack-Surface Asset Graph & Attack-Path Correlation Engine (Phase 4).

Models discovered infrastructure, services, vulnerabilities, and evidence as a
relational graph, deriving deterministic attack paths without intrusive exploits.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from redloop.assessment.finding_models import Finding, FindingSeverity


class GraphNodeType(str, Enum):
    HOST = "host"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    SERVICE = "service"
    APPLICATION = "application"
    CERTIFICATE = "certificate"
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    EVIDENCE = "evidence"


class GraphRelationType(str, Enum):
    RESOLVES_TO = "RESOLVES_TO"
    HOSTS = "HOSTS"
    RUNS = "RUNS"
    EXPOSES = "EXPOSES"
    USES_CERTIFICATE = "USES_CERTIFICATE"
    AFFECTED_BY = "AFFECTED_BY"
    CORRELATED_WITH = "CORRELATED_WITH"
    CONFIRMED_BY = "CONFIRMED_BY"
    PREREQUISITE_FOR = "PREREQUISITE_FOR"
    CONFLICTS_WITH = "CONFLICTS_WITH"
    HAS_FINDING = "HAS_FINDING"


NodeType = GraphNodeType
EdgeRelation = GraphRelationType


class AttackPathType(str, Enum):
    OBSERVED_PATH = "OBSERVED_PATH"
    POTENTIAL_PATH = "POTENTIAL_PATH"
    HYPOTHETICAL_PATH = "HYPOTHETICAL_PATH"
    UNVERIFIED_RELATIONSHIP = "UNVERIFIED_RELATIONSHIP"


@dataclass
class GraphNode:
    node_id: str
    node_type: GraphNodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": {
                "id": self.node_id,
                "label": self.label,
                "type": self.node_type.value,
                **self.properties,
            }
        }


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: GraphRelationType
    edge_id: str = ""
    evidence_id: str | None = None
    basis: str = ""
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.edge_id:
            self.edge_id = f"edge-{self.source_id}->{self.target_id}:{self.relation.value}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": {
                "id": self.edge_id,
                "source": self.source_id,
                "target": self.target_id,
                "relation": self.relation.value,
                "evidence_id": self.evidence_id,
                "basis": self.basis,
                **self.properties,
            }
        }


@dataclass
class AttackPath:
    path_id: str
    title: str
    path_type: AttackPathType
    starting_asset: str
    target_asset: str
    steps: list[dict[str, Any]]
    cumulative_risk: float
    confidence: float
    prerequisites: list[str]
    potential_impact: str
    supporting_evidence_ids: list[str]
    missing_evidence: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.title

    @property
    def entry_node_id(self) -> str:
        return self.starting_asset

    @property
    def target_node_id(self) -> str:
        return self.target_asset

    @property
    def estimated_likelihood(self) -> float:
        return self.confidence

    @property
    def description(self) -> str:
        return self.potential_impact

    @property
    def path_nodes(self) -> list[str]:
        nodes = [self.starting_asset]
        for s in self.steps:
            target = s.get("target") or s.get("node_id") or s.get("asset") or s.get("action")
            if target and target not in nodes:
                nodes.append(target)
        if self.target_asset not in nodes:
            nodes.append(self.target_asset)
        return nodes

    def model_dump(self) -> dict[str, Any]:
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["name"] = self.name
        d["entry_node_id"] = self.entry_node_id
        d["target_node_id"] = self.target_node_id
        d["estimated_likelihood"] = self.estimated_likelihood
        d["description"] = self.description
        d["path_nodes"] = self.path_nodes
        return d


class AssetAttackGraph:
    """Manages the asset entity graph and traverses evidence-backed attack paths."""

    def __init__(self, target: str = "default", task_id: str = "default") -> None:
        self.target = target
        self.task_id = task_id
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []

    def add_node(
        self,
        node_or_id: str | GraphNode,
        node_type: GraphNodeType | None = None,
        label: str = "",
        **properties: Any,
    ) -> GraphNode:
        if isinstance(node_or_id, GraphNode):
            node = node_or_id
            self.nodes[node.node_id] = node
            return node
        node_id = str(node_or_id)
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                node_id=node_id,
                node_type=node_type or GraphNodeType.HOST,
                label=label or node_id,
                properties=properties,
            )
        else:
            self.nodes[node_id].properties.update(properties)
        return self.nodes[node_id]

    def add_edge(
        self,
        edge_or_source: str | GraphEdge,
        target_id: str | None = None,
        relation: GraphRelationType | None = None,
        evidence_id: str | None = None,
        basis: str = "",
        **properties: Any,
    ) -> GraphEdge:
        if isinstance(edge_or_source, GraphEdge):
            edge = edge_or_source
            self.edges.append(edge)
            return edge
        source_id = str(edge_or_source)
        assert target_id is not None and relation is not None
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            edge_id=f"edge-{uuid.uuid4().hex[:8]}",
            evidence_id=evidence_id,
            basis=basis,
            properties=properties,
        )
        self.edges.append(edge)
        return edge

    def populate_from_findings(self, findings: list[Finding]) -> None:
        """Constructs graph nodes and edges directly from normalized findings."""
        for f in findings:
            target_node_id = f"asset:{f.target}"
            self.add_node(
                node_or_id=target_node_id,
                node_type=GraphNodeType.IP_ADDRESS if f.target_type == "ip" else GraphNodeType.DOMAIN,
                label=f.target,
                target_type=f.target_type,
            )

            # If port exists
            if f.port:
                port_node_id = f"port:{f.target}:{f.port}"
                self.add_node(
                    node_or_id=port_node_id,
                    node_type=GraphNodeType.PORT,
                    label=f"{f.port}/{f.protocol or 'tcp'}",
                    port=f.port,
                    protocol=f.protocol,
                )
                self.add_edge(
                    edge_or_source=target_node_id,
                    target_id=port_node_id,
                    relation=GraphRelationType.EXPOSES,
                    evidence_id=f.raw_evidence_id,
                    basis=f"Port scan enumeration by {f.source_tool}",
                )

                # Service node
                if f.affected_component and f.affected_component != "unknown":
                    svc_node_id = f"service:{f.target}:{f.port}:{f.affected_component}"
                    self.add_node(
                        node_or_id=svc_node_id,
                        node_type=GraphNodeType.SERVICE,
                        label=f"{f.affected_component} ({f.affected_version or 'detected'})",
                        component=f.affected_component,
                        version=f.affected_version,
                    )
                    self.add_edge(
                        edge_or_source=port_node_id,
                        target_id=svc_node_id,
                        relation=GraphRelationType.RUNS,
                        evidence_id=f.raw_evidence_id,
                        basis="Banner or protocol probe match",
                    )

            # Vulnerability node
            if f.cve_ids or f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM):
                vuln_node_id = f"vuln:{f.finding_id}"
                self.add_node(
                    node_or_id=vuln_node_id,
                    node_type=GraphNodeType.VULNERABILITY,
                    label=f.title,
                    severity=f.severity.value,
                    cvss=f.cvss_score,
                    cves=f.cve_ids,
                )
                source_parent = f"port:{f.target}:{f.port}" if f.port else target_node_id
                self.add_edge(
                    edge_or_source=source_parent,
                    target_id=vuln_node_id,
                    relation=GraphRelationType.AFFECTED_BY,
                    evidence_id=f.raw_evidence_id,
                    basis=f"Security assessment detection ({f.source_tool})",
                )

    def derive_attack_paths(self) -> list[AttackPath]:
        """Synthesizes deterministic, evidence-backed potential attack paths."""
        paths: list[AttackPath] = []

        # Find exposed services with associated high or critical vulnerabilities
        for edge in self.edges:
            if edge.relation in (GraphRelationType.AFFECTED_BY, GraphRelationType.HAS_FINDING):
                vuln_node = self.nodes.get(edge.target_id)
                svc_or_port_node = self.nodes.get(edge.source_id)

                if vuln_node and svc_or_port_node:
                    cvss = float(vuln_node.properties.get("cvss", 5.0))
                    cves = vuln_node.properties.get("cves", [])

                    # Find entry root
                    entry_id = svc_or_port_node.node_id
                    for e in self.edges:
                        if e.target_id == svc_or_port_node.node_id:
                            entry_id = e.source_id
                            break

                    p_type = AttackPathType.OBSERVED_PATH if "CISA_KEV" in str(vuln_node.properties) else AttackPathType.POTENTIAL_PATH
                    paths.append(
                        AttackPath(
                            path_id=f"path-{uuid.uuid4().hex[:8]}",
                            title=f"Perimeter Exposure: Exploitation of {vuln_node.label}",
                            path_type=p_type,
                            starting_asset=entry_id,
                            target_asset=vuln_node.node_id,
                            steps=[
                                {
                                    "stage": 1,
                                    "action": "External Network Reachability",
                                    "asset": entry_id,
                                    "target": svc_or_port_node.node_id,
                                    "status": "VERIFIED_EXPOSED",
                                },
                                {
                                    "stage": 2,
                                    "action": f"Exploit Delivery ({', '.join(cves) if cves else vuln_node.label})",
                                    "asset": svc_or_port_node.node_id,
                                    "target": vuln_node.node_id,
                                    "status": "POTENTIAL_EXPLOITABLE",
                                },
                            ],
                            cumulative_risk=round(cvss * (1.2 if p_type == AttackPathType.OBSERVED_PATH else 0.9), 1),
                            confidence=0.85 if cves else 0.65,
                            prerequisites=[
                                f"Direct TCP connectivity to {svc_or_port_node.label}",
                                "Absence of network intrusion prevention (WAF/IPS) blocking payload",
                            ],
                            potential_impact="Service compromise or unauthorized data disclosure",
                            supporting_evidence_ids=[edge.evidence_id] if edge.evidence_id else [],
                        )
                    )

        return paths

    def export_cytoscape(self) -> dict[str, Any]:
        return self.to_cytoscape()

    def to_cytoscape(self) -> dict[str, Any]:
        """Exports graph in Cytoscape format for web visualization."""
        elements = {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }
        return {
            "task_id": self.task_id,
            "target": self.target,
            "elements": elements,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }
