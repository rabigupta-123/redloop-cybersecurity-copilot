"""Attack-surface graph and deterministic finding correlation engine.

Maps:
Asset -> IP -> Port -> Service -> Technology -> Endpoint -> Finding -> Evidence

Identifies contextual compound risk without fabricating evidence.
"""

from __future__ import annotations

from typing import Any
from redloop.assessment.models import AttackSurfaceGraph, Finding, Severity


class AttackSurfaceCorrelator:
    """Builds the attack-surface relationship graph and correlates compound findings."""

    def __init__(self) -> None:
        self.graph = AttackSurfaceGraph()

    def populate(
        self,
        target: str,
        ports: list[dict[str, Any]] | None = None,
        endpoints: list[str] | None = None,
        technologies: list[str] | None = None,
        findings: list[Finding] | None = None,
    ) -> AttackSurfaceGraph:
        """Construct the attack-surface graph for the assessed target."""
        # Target Host Node
        self.graph.add_node(f"host:{target}", "host", target)

        # Ports & Services
        if ports:
            for p in ports:
                port_num = p.get("port")
                service_name = p.get("service") or "unknown"
                port_id = f"port:{target}:{port_num}"
                service_id = f"service:{target}:{port_num}:{service_name}"

                self.graph.add_node(port_id, "port", f"Port {port_num}/tcp", port=port_num)
                self.graph.add_edge(f"host:{target}", port_id, "exposes")

                self.graph.add_node(service_id, "service", service_name, **p)
                self.graph.add_edge(port_id, service_id, "runs")

        # Technologies
        if technologies:
            for tech in technologies:
                tech_id = f"tech:{target}:{tech}"
                self.graph.add_node(tech_id, "technology", tech)
                self.graph.add_edge(f"host:{target}", tech_id, "implements")

        # Endpoints
        if endpoints:
            for ep in endpoints:
                ep_id = f"endpoint:{target}:{ep}"
                self.graph.add_node(ep_id, "endpoint", ep)
                self.graph.add_edge(f"host:{target}", ep_id, "exposes")

        # Findings
        if findings:
            for f in findings:
                finding_id = f"finding:{f.id}"
                self.graph.add_node(
                    finding_id,
                    "finding",
                    f.title,
                    severity=f.severity.value,
                    category=f.category,
                )
                if f.port:
                    self.graph.add_edge(f"port:{target}:{f.port}", finding_id, "vulnerable_to")
                elif f.endpoint:
                    self.graph.add_edge(f"endpoint:{target}:{f.endpoint}", finding_id, "vulnerable_to")
                else:
                    self.graph.add_edge(f"host:{target}", finding_id, "vulnerable_to")

        return self.graph

    def correlate_attack_chains(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Identify deterministic multi-finding risk chains.

        Uses measured, conservative language (Section 36).
        """
        chains: list[dict[str, Any]] = []
        categories = {f.category.lower(): f for f in findings}
        titles_lower = [f.title.lower() for f in findings]

        # Chain 1: Insecure Transport + Sensitive Endpoint / Cookies
        has_tls_issue = any("tls" in cat or "ssl" in cat for cat in categories) or any(
            "tls" in t or "https" in t or "certificate" in t for t in titles_lower
        )
        has_auth_or_session = any(
            "cookie" in t or "auth" in t or "login" in t or "session" in t
            for t in titles_lower
        )
        if has_tls_issue and has_auth_or_session:
            chains.append({
                "chain_id": "CHAIN-TLS-AUTH",
                "name": "Weak Transport Across Sensitive Authentication/Session Surface",
                "risk_increase": "High",
                "findings": [
                    f.id
                    for f in findings
                    if any(term in f.title.lower() for term in ("tls", "ssl", "cookie", "auth", "login"))
                ],
                "description": (
                    "Observed transport weaknesses in conjunction with authentication/session indicators "
                    "increase the risk of session interception or credential exposure on adjacent networks."
                ),
            })

        # Chain 2: Information Disclosure + Outdated Tech / Exposed Admin
        has_disclosure = any("disclosure" in t or "header" in t for t in titles_lower)
        has_admin = any("admin" in t or "debug" in t for t in titles_lower)
        if has_disclosure and has_admin:
            chains.append({
                "chain_id": "CHAIN-DISC-ADMIN",
                "name": "Component Disclosure With Exposed Management Interface",
                "risk_increase": "Medium",
                "findings": [
                    f.id
                    for f in findings
                    if any(term in f.title.lower() for term in ("disclosure", "header", "admin", "debug"))
                ],
                "description": (
                    "Technology disclosure banners combined with exposed administrative interfaces "
                    "reduce reconnaissance complexity and increase attack surface visibility."
                ),
            })

        # Normalize finding_ids field in all returned chains
        for ch in chains:
            ch["finding_ids"] = ch.get("findings", [])

        return chains

    def build_graph(
        self,
        target: str,
        findings: list[Finding] | None = None,
        ports: list[dict[str, Any]] | None = None,
        endpoints: list[str] | None = None,
        technologies: list[str] | None = None,
    ) -> AttackSurfaceGraph:
        """Alias for populate()."""
        return self.populate(
            target=target,
            ports=ports,
            endpoints=endpoints,
            technologies=technologies,
            findings=findings,
        )

    def detect_attack_chains(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Alias for correlate_attack_chains()."""
        return self.correlate_attack_chains(findings)
