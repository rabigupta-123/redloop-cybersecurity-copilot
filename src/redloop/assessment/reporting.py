"""Multi-tier security assessment reporting engine for RedLoop.

Strictly adheres to:
- Section 32:
  - Executive report (overall risk, critical/high findings, attack surface, remediation priorities)
  - Technical report (comprehensive details, detections, impacts, remediations, references)
  - Attack-surface report (hosts, IPs, ports, services, technologies, endpoints, APIs)
  - Evidence report (exact request/response, tool output, sha256 evidence integrity hashes)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redloop.assessment.analyst import AIAnalysisResult
from redloop.assessment.models import AssessmentState, Finding, Severity


class ReportingEngine:
    """Generates professional, verifiable security assessment reports across 4 tiers."""

    def generate_executive_report(
        self,
        state: AssessmentState,
        ai_result: AIAnalysisResult | None = None,
    ) -> str:
        """Generate high-level executive report focusing on risk and business posture."""
        crit_count = sum(1 for f in state.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in state.findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in state.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in state.findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in state.findings if f.severity == Severity.INFO)

        # Compute aggregate posture score (10.0 is worst, 0.0 is clean)
        max_risk = max([f.risk_score for f in state.findings], default=0.0)
        avg_risk = (
            round(sum(f.risk_score for f in state.findings) / len(state.findings), 1)
            if state.findings
            else 0.0
        )

        lines = [
            f"# Executive Security Assessment Report",
            f"**Target:** `{state.target}`  ",
            f"**Assessment ID:** `{state.id}`  ",
            f"**Assessment Depth:** `{state.depth.value}`  ",
            f"**Date:** `{state.updated_at}`  ",
            "",
            "## 1. Executive Summary & Overall Risk Posture",
            "",
        ]

        if ai_result and ai_result.executive_summary:
            lines.append(ai_result.executive_summary)
            lines.append(f"\n*(Analyst Confidence: {ai_result.ai_confidence.value})*")
        else:
            lines.append(
                f"Automated evaluation completed across authorized domains. "
                f"Identified {len(state.findings)} total findings across evaluated attack surfaces."
            )

        lines.extend([
            "",
            "### Risk Scorecard",
            f"- **Peak Risk Score:** `{max_risk} / 10.0`",
            f"- **Average Risk Score:** `{avg_risk} / 10.0`",
            f"- **Critical Severity:** `{crit_count}`",
            f"- **High Severity:** `{high_count}`",
            f"- **Medium Severity:** `{med_count}`",
            f"- **Low Severity:** `{low_count}`",
            f"- **Informational:** `{info_count}`",
            "",
            "## 2. Attack Surface Highlights",
            f"- **Discovered Graph Nodes:** `{len(state.graph.nodes)}`",
            f"- **Discovered Interconnections:** `{len(state.graph.edges)}`",
            f"- **Verified Evidence Artifacts:** `{len(state.evidence)}`",
            "",
            "## 3. Immediate Remediation Priorities",
            "",
        ])

        top_findings = sorted(
            [f for f in state.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)],
            key=lambda x: x.risk_score,
            reverse=True,
        )

        if not top_findings:
            lines.append("No Critical or High severity findings requiring emergency intervention were identified.")
        else:
            for idx, f in enumerate(top_findings[:5], 1):
                lines.append(f"### {idx}. {f.title} (Risk: {f.risk_score}/10.0 - {f.severity.value})")
                lines.append(f"- **Affected Asset:** `{f.asset}`")
                lines.append(f"- **Impact:** {f.impact or 'System compromise or credential leakage.'}")
                lines.append(f"- **Recommended Action:** {f.remediation or 'Apply security updates and restrict access.'}")
                lines.append("")

        return "\n".join(lines)

    def generate_technical_report(self, state: AssessmentState) -> str:
        """Generate detailed technical report with exhaustive reproduction guidance."""
        lines = [
            f"# Technical Security Assessment Report",
            f"**Target:** `{state.target}` | **ID:** `{state.id}` | **Depth:** `{state.depth.value}`",
            "",
            "## Discovered Findings",
            "",
        ]

        if not state.findings:
            lines.append("No technical security findings were recorded during this assessment.")
            return "\n".join(lines)

        for idx, f in enumerate(state.findings, 1):
            lines.extend([
                f"### {idx}. [{f.severity.value}] {f.title} (`{f.id}`)",
                f"- **Category:** `{f.category}`",
                f"- **Confidence:** `{f.confidence.value}`",
                f"- **Asset:** `{f.asset}`",
                f"- **Target / Endpoint:** `{f.endpoint or f.target}`",
                f"- **Port / Protocol:** `{f.port or 'N/A'}` / `{f.protocol}`",
                f"- **Detection Method:** `{f.detection_method}`",
                f"- **Risk Score:** `{f.risk_score} / 10.0`",
                f"- **Score Rationale:** {f.risk_explanation}",
                "",
                "#### Description",
                f"{f.description}",
                "",
                "#### Technical Impact",
                f"{f.impact or 'Exposure of internal data or elevation of attacker capabilities.'}",
                "",
                "#### Remediation Guidance",
                f"{f.remediation or 'Harden system configuration according to security standards.'}",
                "",
            ])

            if f.references:
                lines.append("#### References")
                for r in f.references:
                    lines.append(f"- {r}")
                lines.append("")

            if f.evidence:
                lines.append("#### Associated Evidence Hashes")
                for ev in f.evidence:
                    lines.append(f"- SHA256: `{ev.sha256_hash}` (Timestamp: `{ev.timestamp}`)")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def generate_attack_surface_report(self, state: AssessmentState) -> str:
        """Generate attack surface asset topology report."""
        lines = [
            f"# Attack Surface Topology Report",
            f"**Target:** `{state.target}` | **Assessment ID:** `{state.id}`",
            "",
            "## Discovered Attack Surface Entities",
            "",
            "| Node ID | Type | Label | Properties |",
            "| --- | --- | --- | --- |",
        ]

        if not state.graph.nodes:
            lines.append("| None | N/A | No entities discovered | {} |")
        else:
            for n in state.graph.nodes:
                props_str = json.dumps(n.properties)[:80]
                lines.append(f"| `{n.id}` | `{n.type}` | `{n.label}` | `{props_str}` |")

        lines.extend([
            "",
            "## Entity Relationships",
            "",
            "| Source | Relationship | Target |",
            "| --- | --- | --- |",
        ])

        if not state.graph.edges:
            lines.append("| None | N/A | None |")
        else:
            for e in state.graph.edges:
                lines.append(f"| `{e.source}` | `{e.relationship}` | `{e.target}` |")

        return "\n".join(lines)

    def generate_evidence_report(self, state: AssessmentState) -> str:
        """Generate verifiable evidence ledger with cryptographic integrity hashes."""
        lines = [
            f"# Assessment Evidence Integrity Ledger",
            f"**Target:** `{state.target}` | **Assessment ID:** `{state.id}`",
            "",
            "Each evidence artifact is deterministically verified with SHA-256 for chain of custody.",
            "",
        ]

        if not state.evidence:
            lines.append("No evidence records captured.")
            return "\n".join(lines)

        for idx, ev in enumerate(state.evidence, 1):
            lines.extend([
                f"### Evidence #{idx} (`{ev.id}`)",
                f"- **Timestamp:** `{ev.timestamp}`",
                f"- **Target:** `{ev.target}`",
                f"- **Operation ID:** `{ev.operation_id}`",
                f"- **Integrity Hash (SHA256):** `{ev.sha256_hash}`",
                "",
            ])

            if ev.response_excerpt:
                lines.extend([
                    "**Response Excerpt:**",
                    "```text",
                    ev.response_excerpt[:2000],
                    "```",
                    "",
                ])

            if ev.tool_output:
                lines.extend([
                    "**Tool Output:**",
                    "```text",
                    ev.tool_output[:2000],
                    "```",
                    "",
                ])

            if ev.parser_result:
                lines.extend([
                    "**Structured Parser Data:**",
                    "```json",
                    json.dumps(ev.parser_result, indent=2)[:2000],
                    "```",
                    "",
                ])

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def export_all(
        self,
        state: AssessmentState,
        output_dir: str | Path,
        ai_result: AIAnalysisResult | None = None,
    ) -> dict[str, Path]:
        """Save all 4 report variants into output directory."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        exec_path = out / f"assessment_{state.id}_executive.md"
        tech_path = out / f"assessment_{state.id}_technical.md"
        surf_path = out / f"assessment_{state.id}_attack_surface.md"
        evid_path = out / f"assessment_{state.id}_evidence.md"

        exec_path.write_text(self.generate_executive_report(state, ai_result), encoding="utf-8")
        tech_path.write_text(self.generate_technical_report(state), encoding="utf-8")
        surf_path.write_text(self.generate_attack_surface_report(state), encoding="utf-8")
        evid_path.write_text(self.generate_evidence_report(state), encoding="utf-8")

        return {
            "executive": exec_path,
            "technical": tech_path,
            "attack_surface": surf_path,
            "evidence": evid_path,
        }
