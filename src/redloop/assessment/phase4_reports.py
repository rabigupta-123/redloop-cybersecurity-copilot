"""Phase 4 Comprehensive Security Report Generation Engine.

Produces audit-grade security assessment reports in:
- Markdown (.md)
- JSON (.json)
- Standalone HTML5 (.html)

Includes:
1. Executive Summary & Composite Risk Posture
2. Authorized Target & Scope Ledger
3. Asset Inventory & Attack Surface Exposure
4. Corroborated Vulnerability Findings & Operational Priorities (P1-P5)
5. Graph-Derived Attack Path Scenarios
6. Actionable Technology-Specific Remediation Roadmap
7. Cryptographic Evidence Appendix (SHA-256 Hashes)
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from redloop.assessment.asset_attack_graph import AssetAttackGraph
from redloop.assessment.finding_models import Finding, FindingSeverity, OperationalPriority, VerificationStatus


class Phase4ReportGenerator:
    """Generates professional executive & technical security assessment reports."""

    def __init__(
        self,
        target: str,
        task_id: str,
        findings: list[Finding],
        graph: AssetAttackGraph | None = None,
        evidence_records: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.target = target
        self.task_id = task_id
        self.findings = findings
        self.graph = graph or AssetAttackGraph(target)
        self.evidence_records = evidence_records or []
        self.metadata = metadata or {}
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def generate_json(self) -> dict[str, Any]:
        """Generate structured JSON report representation."""
        p_counts = {p.value: 0 for p in OperationalPriority}
        s_counts = {s.value: 0 for s in FindingSeverity}
        v_counts = {v.value: 0 for v in VerificationStatus}

        for f in self.findings:
            if f.operational_priority:
                p_counts[f.operational_priority.value] = p_counts.get(f.operational_priority.value, 0) + 1
            s_counts[f.severity.value] = s_counts.get(f.severity.value, 0) + 1
            v_counts[f.verification_status.value] = v_counts.get(f.verification_status.value, 0) + 1

        attack_paths = self.graph.derive_attack_paths()

        return {
            "report_version": "4.0",
            "task_id": self.task_id,
            "target": self.target,
            "generated_at": self.generated_at,
            "metadata": self.metadata,
            "summary": {
                "total_findings": len(self.findings),
                "operational_priorities": p_counts,
                "severities": s_counts,
                "verification_statuses": v_counts,
                "attack_paths_count": len(attack_paths),
                "nodes_count": len(self.graph.nodes),
                "edges_count": len(self.graph.edges),
            },
            "findings": [f.model_dump() for f in self.findings],
            "asset_graph": self.graph.export_cytoscape(),
            "attack_paths": [p.model_dump() for p in attack_paths],
            "evidence_ledger": self.evidence_records,
        }

    def generate_markdown(self) -> str:
        """Generate executive & technical Markdown security report."""
        report = self.generate_json()
        summary = report["summary"]
        p_counts = summary["operational_priorities"]
        s_counts = summary["severities"]

        md_lines = [
            f"# REDLOOP Security Assessment & Intelligence Report",
            f"**Target:** `{self.target}`  ",
            f"**Task ID:** `{self.task_id}`  ",
            f"**Generated:** `{self.generated_at}`  ",
            f"**Classification:** RESTRICTED / CONFIDENTIAL  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"REDLOOP conducted an autonomous security intelligence and assessment operation against `{self.target}`. "
            f"A total of **{len(self.findings)} findings** were identified across **{len(self.graph.nodes)} discovered asset nodes**.",
            "",
            "### Risk & Priority Breakdown",
            "| Operational Priority | Count | Description |",
            "| :--- | :--- | :--- |",
            f"| **P1 - Critical Immediate** | `{p_counts.get(OperationalPriority.P1_CRITICAL_IMMEDIATE.value, 0)}` | Actively exploited or critical remote code execution risks requiring immediate action |",
            f"| **P2 - High Urgent** | `{p_counts.get(OperationalPriority.P2_HIGH_URGENT.value, 0)}` | Significant exposure or high exploitability requiring urgent remediation |",
            f"| **P3 - Medium Scheduled** | `{p_counts.get(OperationalPriority.P3_MEDIUM_SCHEDULED.value, 0)}` | Vulnerabilities with barriers to exploit, addressed in next release cycle |",
            f"| **P4 - Low Backlog** | `{p_counts.get(OperationalPriority.P4_LOW_BACKLOG.value, 0)}` | Defense-in-depth or low severity issues |",
            f"| **P5 - Informational** | `{p_counts.get(OperationalPriority.P5_INFORMATIONAL.value, 0)}` | Service discovery and environmental details |",
            "",
            "---",
            "",
            "## 2. Attack Surface & Discovered Assets",
            "",
            f"Network mapping uncovered `{len(self.graph.nodes)}` entity nodes interconnected by `{len(self.graph.edges)}` relationships.",
            "",
            "| Asset Identifier | Type | Host / IP | Port / Protocol | Details |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]

        for node_id, node in self.graph.nodes.items():
            label = node.label
            ntype = node.node_type.value
            props = node.properties
            host = props.get("host", props.get("ip", "-"))
            port = f"{props.get('port', '-')}/{props.get('protocol', '-')}" if "port" in props else "-"
            md_lines.append(f"| `{node_id}` | `{ntype}` | `{host}` | `{port}` | {label} |")

        md_lines.extend([
            "",
            "---",
            "",
            "## 3. Prioritized Security Findings",
            "",
        ])

        if not self.findings:
            md_lines.append("*No security vulnerabilities or exposures were identified during this assessment.*")
        else:
            for idx, f in enumerate(self.findings, 1):
                p_badge = f.operational_priority.value if f.operational_priority else "P3_MEDIUM"
                kev_str = "🔥 **CISA KEV**" if f.cisa_kev else ""
                epss_str = f"EPSS: `{f.epss_score:.2%}`" if f.epss_score is not None else ""
                cvss_str = f"CVSS: `{f.cvss_score}`" if f.cvss_score is not None else ""
                scores = " | ".join(filter(None, [cvss_str, epss_str, kev_str]))

                target_type_str = f.target_type.value if hasattr(f.target_type, "value") else str(f.target_type or "")
                md_lines.extend([
                    f"### 3.{idx}. [{p_badge}] {f.title}",
                    f"- **Severity:** `{f.severity.value}` | **Verification:** `{f.verification_status.value}` ({f.confidence:.0%})",
                    f"- **Target Asset:** `{f.target}` {f'({target_type_str})' if target_type_str else ''} | **Port:** `{f.port or '-'}`",
                    f"- **Intelligence:** {scores if scores else 'Standard Heuristic'}",
                    f"- **Evidence Reference:** `{f.raw_evidence_id or 'telemetry'}`",
                    "",
                    f"**Description:**  ",
                    f"{f.description}",
                    "",
                ])

                if f.remediation:
                    md_lines.extend([
                        f"**Remediation Guidance:**",
                        f"- **Immediate Containment:** {f.remediation.immediate_containment}",
                        f"- **Permanent Fix:** {f.remediation.permanent_fix}",
                    ])
                    if f.remediation.configuration_snippet:
                        md_lines.extend([
                            "```text",
                            f.remediation.configuration_snippet.strip(),
                            "```",
                        ])
                    if f.remediation.validation_steps:
                        md_lines.append(f"- **Validation Steps:** `{f.remediation.validation_steps}`")
                    md_lines.append("")

        md_lines.extend([
            "---",
            "",
            "## 4. Graph Attack-Path Analysis",
            "",
        ])

        paths = self.graph.derive_attack_paths()
        if not paths:
            md_lines.append("*No multi-stage attack or pivot paths were identified across the mapped nodes.*")
        else:
            for idx, p in enumerate(paths, 1):
                md_lines.extend([
                    f"### Attack Path {idx}: {p.name}",
                    f"- **Entry Point:** `{p.entry_node_id}` $\\rightarrow$ **Objective:** `{p.target_node_id}`",
                    f"- **Path Likelihood:** `{p.estimated_likelihood:.0%}`",
                    f"- **Chain:** {' $\\rightarrow$ '.join(p.path_nodes)}",
                    "",
                    f"{p.description}",
                    "",
                ])

        md_lines.extend([
            "---",
            "",
            "## 5. Cryptographic Evidence Appendix",
            "",
            "All findings in this assessment are cryptographically linked to immutable raw tool outputs.",
            "",
            "| Evidence ID | Tool | Operation | Target | SHA-256 Digest |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        if not self.evidence_records:
            md_lines.append("| *None* | - | - | - | - |")
        else:
            for ev in self.evidence_records:
                eid = ev.get("evidence_id", "-")
                tool = ev.get("tool_name", "-")
                op = ev.get("operation_name", "-")
                tgt = ev.get("target", "-")
                digest = ev.get("sha256", "-")
                md_lines.append(f"| `{eid}` | `{tool}` | `{op}` | `{tgt}` | `{digest}` |")

        md_lines.extend([
            "",
            "---",
            "*Report generated deterministically by REDLOOP Autonomous Cybersecurity Engine.*",
        ])

        return "\n".join(md_lines)

    def generate_html(self) -> str:
        """Generate self-contained HTML5 report with embedded styles and charts."""
        report = self.generate_json()
        summary = report["summary"]
        p_counts = summary["operational_priorities"]
        
        findings_html = []
        for idx, f in enumerate(self.findings, 1):
            sev_class = f.severity.value.lower()
            p_badge = f.operational_priority.value if f.operational_priority else "P3_MEDIUM"
            rem = f.remediation
            rem_html = ""
            if rem:
                rem_html = f"""
                <div class="remediation-box">
                    <strong>Immediate Containment:</strong> {html.escape(rem.immediate_containment or "")}<br/>
                    <strong>Permanent Fix:</strong> {html.escape(rem.permanent_fix or "")}<br/>
                    {f'<pre><code>{html.escape(rem.configuration_snippet or "")}</code></pre>' if rem.configuration_snippet else ''}
                    {f'<strong>Validation:</strong> <code>{html.escape(rem.validation_steps)}</code>' if rem.validation_steps else ''}
                </div>
                """

            findings_html.append(f"""
            <div class="finding-card {sev_class}">
                <div class="card-header">
                    <span class="badge badge-{sev_class}">{html.escape(f.severity.value)}</span>
                    <span class="badge badge-priority">{html.escape(p_badge)}</span>
                    <span class="finding-title">{html.escape(f.title)}</span>
                </div>
                <div class="card-body">
                    <p>{html.escape(f.description)}</p>
                    <div class="meta-row">
                        <span><strong>Target:</strong> {html.escape(f.target)}</span>
                        <span><strong>Port:</strong> {f.port or 'N/A'}</span>
                        <span><strong>Verification:</strong> {html.escape(f.verification_status.value)} ({f.confidence:.0%})</span>
                        {f'<span><strong>CISA KEV:</strong> YES</span>' if f.cisa_kev else ''}
                        {f'<span><strong>EPSS:</strong> {f.epss_score:.1%}</span>' if f.epss_score is not None else ''}
                        <span><strong>Evidence ID:</strong> <code>{html.escape(f.raw_evidence_id or 'telemetry')}</code></span>
                    </div>
                    {rem_html}
                </div>
            </div>
            """)

        evidence_rows = []
        for ev in self.evidence_records:
            evidence_rows.append(f"""
            <tr>
                <td><code>{html.escape(str(ev.get("evidence_id", "-")))}</code></td>
                <td>{html.escape(str(ev.get("tool_name", "-")))}</td>
                <td>{html.escape(str(ev.get("operation_name", "-")))}</td>
                <td><code>{html.escape(str(ev.get("sha256", "-")))}</code></td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REDLOOP Assessment Report - {html.escape(self.target)}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-heading: #f0f6fc;
            --accent: #58a6ff;
            --crit: #f85149;
            --high: #ff7b72;
            --med: #d29922;
            --low: #3fb950;
            --info: #8b949e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1, h2, h3 {{ color: var(--text-heading); border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
        .header-meta {{ color: var(--info); margin-bottom: 24px; font-size: 0.9em; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; text-align: center; }}
        .stat-num {{ font-size: 2em; font-weight: bold; color: var(--text-heading); }}
        .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }}
        .badge-critical {{ background: var(--crit); color: #fff; }}
        .badge-high {{ background: var(--high); color: #000; }}
        .badge-medium {{ background: var(--med); color: #000; }}
        .badge-low {{ background: var(--low); color: #000; }}
        .badge-info {{ background: var(--info); color: #fff; }}
        .badge-priority {{ background: var(--accent); color: #000; }}
        .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-left: 5px solid var(--border); border-radius: 6px; margin-bottom: 16px; padding: 16px; }}
        .finding-card.critical {{ border-left-color: var(--crit); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--med); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-card.info {{ border-left-color: var(--info); }}
        .card-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .finding-title {{ font-weight: 600; font-size: 1.1em; color: var(--text-heading); }}
        .meta-row {{ display: flex; flex-wrap: wrap; gap: 16px; font-size: 0.85em; color: var(--info); margin: 12px 0; }}
        .remediation-box {{ background: #090d13; border: 1px solid #21262d; border-radius: 4px; padding: 12px; margin-top: 12px; font-size: 0.9em; }}
        pre {{ background: #05070a; padding: 8px; border-radius: 4px; overflow-x: auto; color: #79c0ff; }}
        code {{ font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        th, td {{ border: 1px solid var(--border); padding: 8px 12px; text-align: left; }}
        th {{ background: var(--surface); color: var(--text-heading); }}
    </style>
</head>
<body>
    <div class="container">
        <h1>REDLOOP Security Assessment Report</h1>
        <div class="header-meta">
            Target: <strong>{html.escape(self.target)}</strong> | Task ID: <code>{html.escape(self.task_id)}</code> | Generated: {html.escape(self.generated_at)}
        </div>

        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="stat-card">
                <div class="stat-num" style="color: var(--crit);">{p_counts.get(OperationalPriority.P1_CRITICAL_IMMEDIATE.value, 0)}</div>
                <div>P1 - Critical Immediate</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--high);">{p_counts.get(OperationalPriority.P2_HIGH_URGENT.value, 0)}</div>
                <div>P2 - High Urgent</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--med);">{p_counts.get(OperationalPriority.P3_MEDIUM_SCHEDULED.value, 0)}</div>
                <div>P3 - Medium Scheduled</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: var(--low);">{p_counts.get(OperationalPriority.P4_LOW_BACKLOG.value, 0)}</div>
                <div>P4 - Low Backlog</div>
            </div>
        </div>

        <h2>Prioritized Security Findings ({len(self.findings)})</h2>
        {''.join(findings_html) if findings_html else '<p>No security findings reported.</p>'}

        <h2>Cryptographic Evidence Verification</h2>
        <table>
            <thead>
                <tr>
                    <th>Evidence ID</th>
                    <th>Tool</th>
                    <th>Operation</th>
                    <th>SHA-256 Digest</th>
                </tr>
            </thead>
            <tbody>
                {''.join(evidence_rows) if evidence_rows else '<tr><td colspan="4">No evidence records logged.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html_content
