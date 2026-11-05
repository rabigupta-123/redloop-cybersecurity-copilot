"""REDLOOP Phase 10 — Structured Incident & Threat Hunting Investigation Reports Generator.

Provides:
1. Multi-section comprehensive cybersecurity investigation report generation.
2. Structured export in both JSON and Markdown formats.
3. Transparent factual separation: Confirmed Observations vs Inferences vs Hypotheses.
4. Aggregation of timeline events, evaluated hypotheses, process lineages, pivots, and SOAR mitigation actions.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from redloop.assessment.attack_reconstruction import AttackReconstructionEngine, ProcessLineageGraph
from redloop.assessment.case_management import CaseManager
from redloop.assessment.hunting_pivots import PivotGraphResult, ThreatHuntingPivotEngine
from redloop.assessment.hypothesis_manager import HypothesisManager
from redloop.assessment.incident_correlation import IncidentCorrelationEngine
from redloop.assessment.soc_events import UniversalSecurityEvent


@dataclass
class InvestigationReport:
    """Comprehensive structured incident and threat hunting investigation report."""
    report_id: str
    title: str
    target_identifier: str  # Case ID, Incident ID, or Hunt ID
    author: str
    created_at: str
    executive_summary: str
    confirmed_observations: list[str]
    inferred_relationships: list[str]
    hypotheses_evaluated: list[dict[str, Any]]
    attack_reconstruction: Optional[dict[str, Any]]
    entity_pivots: Optional[dict[str, Any]]
    timeline_events: list[dict[str, Any]]
    mitigation_actions: list[dict[str, Any]]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        """Renders the investigation report as a professional GitHub-flavored Markdown document."""
        lines = [
            f"# REDLOOP Threat Investigation Report: {self.title}",
            "",
            f"**Report ID:** `{self.report_id}`  ",
            f"**Target Identifier:** `{self.target_identifier}`  ",
            f"**Author / Lead Hunter:** {self.author}  ",
            f"**Generated At (UTC):** {self.created_at}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            self.executive_summary,
            "",
            "---",
            "",
            "## 2. Confirmed Observations vs Inferences",
            "",
            "### Confirmed Observations (Direct Telemetry)",
        ]
        if self.confirmed_observations:
            for obs in self.confirmed_observations:
                lines.append(f"- [x] {obs}")
        else:
            lines.append("- *No direct telemetry observations recorded.*")

        lines.extend([
            "",
            "### Inferred & Correlated Relationships",
        ])
        if self.inferred_relationships:
            for inf in self.inferred_relationships:
                lines.append(f"- [ ] {inf}")
        else:
            lines.append("- *No heuristic inferences recorded.*")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Threat Hunting Hypotheses Evaluated",
            "",
        ])
        if self.hypotheses_evaluated:
            for hyp in self.hypotheses_evaluated:
                lines.append(f"### Hypothesis: {hyp.get('title')} (`{hyp.get('hypothesis_id')}`)")
                lines.append(f"- **Status:** `{hyp.get('status')}` | **Confidence Score:** `{hyp.get('confidence_score')}`")
                lines.append(f"- **Description:** {hyp.get('description')}")
                lines.append(f"- **MITRE ATT&CK Techniques:** {', '.join(hyp.get('mitre_techniques', [])) or 'None'}")
                lines.append(f"- **Supporting Evidence Count:** {len(hyp.get('supporting_evidence', []))}")
                lines.append(f"- **Contradictory Evidence Count:** {len(hyp.get('contradictory_evidence', []))}")
                if hyp.get("findings_summary"):
                    lines.append(f"- **Findings Summary:** {hyp.get('findings_summary')}")
                lines.append("")
        else:
            lines.append("- *No formal hypotheses linked to this investigation.*")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 4. Attack Reconstruction & Process Lineage",
            "",
        ])
        if self.attack_reconstruction and self.attack_reconstruction.get("nodes"):
            ar = self.attack_reconstruction
            lines.append(f"- **Total Process Nodes:** {len(ar.get('nodes', []))}")
            lines.append(f"- **Suspicious Processes Identified:** {ar.get('suspicious_nodes_count', 0)}")
            lines.append(f"- **ATT&CK Techniques Mapped:** {', '.join(ar.get('attack_techniques_detected', [])) or 'None'}")
            lines.append("")
            lines.append("| Timestamp | Process Name | PID | PPID | User | LOLBin | Indicators |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for node in ar.get("nodes", []):
                lol_tag = "YES" if node.get("is_lolbin") else "No"
                ind_str = "<br>".join(node.get("suspicious_indicators", [])) or "-"
                lines.append(f"| {node.get('timestamp')} | `{node.get('process_name')}` | {node.get('process_id') or '-'} | {node.get('parent_process_id') or '-'} | {node.get('user') or '-'} | {lol_tag} | {ind_str} |")
            lines.append("")
        else:
            lines.append("- *No process lineage data reconstructed.*")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 5. Entity Pivots & Key Indicators",
            "",
        ])
        if self.entity_pivots and self.entity_pivots.get("entities"):
            ep = self.entity_pivots
            lines.append(f"- **Root Entity:** `{ep.get('root_entity_type')}` = `{ep.get('root_entity_value')}`")
            lines.append(f"- **Total Discovered Entities:** {ep.get('total_entities_discovered')}")
            lines.append("")
            for ent_type, vals in ep.get("entities", {}).items():
                lines.append(f"**{ent_type} ({len(vals)}):** " + ", ".join(f"`{v}`" for v in vals))
            lines.append("")
        else:
            lines.append("- *No multi-hop entity pivots performed.*")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 6. Incident Timeline",
            "",
        ])
        if self.timeline_events:
            lines.append("| Time | Event / Action | Actor | Description |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for t in self.timeline_events:
                ts = t.get("timestamp") or t.get("time") or "-"
                act = t.get("event_type") or t.get("action") or "-"
                actor = t.get("actor") or t.get("user") or "system"
                desc = t.get("description") or t.get("details") or "-"
                lines.append(f"| {ts} | {act} | {actor} | {desc} |")
            lines.append("")
        else:
            lines.append("- *No chronological timeline events recorded.*")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 7. Containment & Remediation Actions",
            "",
        ])
        if self.mitigation_actions:
            for act in self.mitigation_actions:
                status_badge = act.get("status", "SUCCESS")
                lines.append(f"- **Action:** `{act.get('action_name')}` on `{act.get('target')}` — Status: `{status_badge}`")
                if act.get("details"):
                    lines.append(f"  *Details:* {act.get('details')}")
            lines.append("")
        else:
            lines.append("- *No active SOAR containment actions dispatched.*")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 8. Strategic Recommendations",
            "",
        ])
        if self.recommendations:
            for rec in self.recommendations:
                lines.append(f"1. {rec}")
        else:
            lines.append("1. Continue monitoring active endpoint and directory event streams.")
            lines.append("2. Implement automated Sigma detection rules for observed execution patterns.")

        return "\n".join(lines)


class InvestigationReportGenerator:
    """Orchestrates comprehensive cross-subsystem report generation."""

    @classmethod
    def generate_case_report(
        cls,
        case_id: str,
        author: str = "security_lead",
        case_mgr: Optional[CaseManager] = None,
    ) -> InvestigationReport:
        """Generates an authoritative investigation report for a CaseManager case."""
        cm = case_mgr or CaseManager.get_instance()
        case = cm.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        corr_engine = IncidentCorrelationEngine.get_instance()
        hyp_mgr = HypothesisManager.get_instance()

        now_iso = datetime.now(timezone.utc).isoformat()
        rid = f"rep-{uuid.uuid4().hex[:10]}"

        # 1. Hypotheses
        linked_hyps = []
        all_hyps = hyp_mgr.list_hypotheses(limit=100)
        for h in all_hyps:
            if case_id in h.get("linked_cases", []):
                linked_hyps.append(h)

        # 2. Timeline
        timeline_events = [e.to_dict() for e in case.timeline]

        # 3. Observations vs Inferences
        confirmed = [
            f"Case '{case.title}' created with severity {case.severity.value} and priority {case.priority.value}.",
            f"Assigned to {case.assigned_to}.",
        ]
        inferred = []
        for inc_id in case.linked_incident_ids:
            inc = corr_engine.get_incident(inc_id)
            if inc:
                confirmed.append(f"Correlated Incident {inc.incident_id} linked with {len(inc.linked_events)} events.")
                inferred.extend([f"Relationship inferred: {rel.relationship_type.value} between entities." for rel in inc.entity_relationships])

        # 4. Summary
        exec_summary = (
            f"Investigation {case.case_id} ('{case.title}') status is currently {case.status.value}. "
            f"Analysis incorporates {len(timeline_events)} timeline entries, {len(case.linked_incident_ids)} correlated incidents, "
            f"and {len(linked_hyps)} evaluated threat hunting hypotheses."
        )

        recs = [
            "Validate endpoint isolation and verify credential revocation for affected accounts.",
            "Deploy Sigma and EDR detection rules targeting identified attack indicators.",
            "Complete case documentation and cryptographically seal case audit trail checkpoint.",
        ]

        return InvestigationReport(
            report_id=rid,
            title=case.title,
            target_identifier=case.case_id,
            author=author,
            created_at=now_iso,
            executive_summary=exec_summary,
            confirmed_observations=confirmed,
            inferred_relationships=inferred,
            hypotheses_evaluated=linked_hyps,
            attack_reconstruction=None,
            entity_pivots=None,
            timeline_events=timeline_events,
            mitigation_actions=[],
            recommendations=recs,
        )

    @classmethod
    def generate_custom_hunt_report(
        cls,
        title: str,
        events: list[UniversalSecurityEvent],
        hypotheses: Optional[list[dict[str, Any]]] = None,
        author: str = "threat_hunter",
        seed_entity: Optional[tuple[str, str]] = None,
    ) -> InvestigationReport:
        """Generates an investigation report from threat hunt events and graph reconstruction."""
        rid = f"rep-hunt-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Attack reconstruction
        lineage_graph = AttackReconstructionEngine.reconstruct_process_lineage(events)

        # Pivots
        pivot_result = None
        if seed_entity:
            e_type, e_val = seed_entity
            pivot_result = ThreatHuntingPivotEngine.execute_pivot(
                entity_type=e_type,
                entity_value=e_val,
                events=events,
            ).to_dict()

        confirmed = [
            f"Analyzed {len(events)} security events across {len(set(e.host for e in events if e.host))} unique hosts.",
            f"Identified {lineage_graph.suspicious_nodes_count} suspicious process execution nodes.",
        ]
        inferred = [
            f"Mapped attack techniques: {', '.join(lineage_graph.attack_techniques_detected) or 'None'}.",
        ]

        timeline = [
            {
                "timestamp": ev.timestamp,
                "event_type": ev.event_action or ev.event_type or "EVENT",
                "actor": ev.user or ev.username or "system",
                "description": f"{ev.process_name or ev.source_type}: {ev.command_line or str(ev.raw_data)[:80]}",
            }
            for ev in events[:25]
        ]

        exec_summary = (
            f"Threat hunting investigation '{title}' reviewed {len(events)} telemetry events. "
            f"Process lineage reconstruction revealed {lineage_graph.suspicious_nodes_count} suspicious execution chains, "
            f"mapping to MITRE ATT&CK techniques: {', '.join(lineage_graph.attack_techniques_detected) or 'None'}."
        )

        return InvestigationReport(
            report_id=rid,
            title=title,
            target_identifier=f"hunt-{uuid.uuid4().hex[:6]}",
            author=author,
            created_at=now_iso,
            executive_summary=exec_summary,
            confirmed_observations=confirmed,
            inferred_relationships=inferred,
            hypotheses_evaluated=hypotheses or [],
            attack_reconstruction=lineage_graph.to_dict(),
            entity_pivots=pivot_result,
            timeline_events=timeline,
            mitigation_actions=[],
            recommendations=[
                "Review suspicious process command lines identified in attack reconstruction.",
                "Isolate compromised endpoints exhibiting malicious LOLBin executions.",
                "Formulate structured hypotheses for lateral movement and persistence.",
            ],
        )
