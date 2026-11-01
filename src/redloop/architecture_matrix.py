"""Open-Source Cybersecurity Architecture Integration Matrix for REDLOOP.

Audits and documents architectural patterns extracted from:
- ARTEX (YuXiangggg/ARTEX-en / Autumn-27)
- PentestGPT (GreyDGL/PentestGPT)
- PentAGI (vxcontrol/pentagi)
- Shannon (KeygraphHQ/shannon)
- IntelOwl (intelowlproject/IntelOwl)
- OWASP ASVS (OWASP/ASVS)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class OSSPattern:
    project_name: str
    repository_url: str
    license_type: str
    architectural_pattern: str
    redloop_module_mapping: str
    solved_problem: str
    implementation_status: str  # IMPLEMENTED, INTEGRATED, ADAPTED
    test_suite: str
    attribution_notes: str


OPEN_SOURCE_ARCHITECTURE_MATRIX: list[OSSPattern] = [
    OSSPattern(
        project_name="ARTEX",
        repository_url="https://github.com/YuXiangggg/ARTEX-en",
        license_type="Apache-2.0 / Community Fork",
        architectural_pattern="Dual-Graph Layout (Asset Graph + Exploration Graph) with Planner-Worker Agents",
        redloop_module_mapping="redloop.assessment.agentic_engine & redloop.investigation_graph",
        solved_problem="Prevents lost context during multi-step scans by decoupling asset topology from execution hypotheses.",
        implementation_status="ADAPTED",
        test_suite="tests/test_agentic_engine.py",
        attribution_notes="Adapted conceptual dual-graph model (Asset vs Exploration) into local SQLite store; no code copied.",
    ),
    OSSPattern(
        project_name="PentestGPT",
        repository_url="https://github.com/GreyDGL/PentestGPT",
        license_type="GPL-3.0 / MIT (Legacy)",
        architectural_pattern="Tripartite Modular Engine (Reasoning Module + Generation Module + Parsing Module)",
        redloop_module_mapping="redloop.assessment.agentic_engine & redloop.assessment.kali_copilot",
        solved_problem="Eliminates LLM context contamination by parsing raw tool outputs before updating the Pentesting Task Tree (PTT).",
        implementation_status="ADAPTED",
        test_suite="tests/test_agentic_engine.py & tests/test_kali_copilot.py",
        attribution_notes="Implemented native Python tripartite workflow without GPL dependencies; independent implementation.",
    ),
    OSSPattern(
        project_name="PentAGI",
        repository_url="https://github.com/vxcontrol/pentagi",
        license_type="Apache-2.0",
        architectural_pattern="Multi-Agent Specialist Swarm (Recon, Web, Exploit, Reporter) with Bounded Task Loop",
        redloop_module_mapping="redloop.assessment.agentic_engine & redloop.assessment.orchestrator",
        solved_problem="Delegates specialized domain tasks to dedicated sub-agents under strict time and iteration budgets.",
        implementation_status="ADAPTED",
        test_suite="tests/test_agentic_engine.py",
        attribution_notes="Implemented specialist agent roles with fail-closed scope enforcement at every tool execution point.",
    ),
    OSSPattern(
        project_name="Shannon",
        repository_url="https://github.com/KeygraphHQ/shannon",
        license_type="Apache-2.0",
        architectural_pattern="Evidence-First Verification Pipeline ('No Exploit, No Report') & Remediation Verification",
        redloop_module_mapping="redloop.assessment.controlled_runner & redloop.remediation",
        solved_problem="Eliminates false-positive AI hallucinations by requiring cryptographic evidence fingerprints and before/after verification.",
        implementation_status="IMPLEMENTED",
        test_suite="tests/test_remediation_and_shannon.py",
        attribution_notes="Adopted proof-of-concept verification criteria and automated remediation re-testing; clean-room implementation.",
    ),
    OSSPattern(
        project_name="IntelOwl",
        repository_url="https://github.com/intelowlproject/IntelOwl",
        license_type="GPL-3.0",
        architectural_pattern="Orchestrated Threat Intelligence Analyzers with Unified Normalized Threat Scoring",
        redloop_module_mapping="redloop.threat_intel",
        solved_problem="Consolidates disparate threat feeds (CVE, CISA KEV, EPSS, AbuseIPDB, VirusTotal) into standardized risk metrics.",
        implementation_status="ADAPTED",
        test_suite="tests/test_threat_intel.py",
        attribution_notes="Built native REST analyzers for CISA KEV, EPSS, NVD, AbuseIPDB, and VirusTotal; supports external IntelOwl REST endpoints.",
    ),
    OSSPattern(
        project_name="OWASP ASVS",
        repository_url="https://github.com/OWASP/ASVS",
        license_type="Creative Commons Attribution-ShareAlike 4.0",
        architectural_pattern="Standardized Security Requirements & Verification Checklist Matrix (v4.0)",
        redloop_module_mapping="redloop.asvs",
        solved_problem="Replaces ad-hoc web testing with structured, reproducible verification levels (V2, V3, V5, V13, V14).",
        implementation_status="IMPLEMENTED",
        test_suite="tests/test_asvs.py",
        attribution_notes="Bundled ASVS v4.0 verification criteria into automated evaluation engine with evidence-backed grading.",
    ),
]


def get_architecture_matrix() -> dict[str, Any]:
    matrix = [asdict(p) for p in OPEN_SOURCE_ARCHITECTURE_MATRIX]
    return {
        "studied_projects": [p.project_name for p in OPEN_SOURCE_ARCHITECTURE_MATRIX],
        "integration_matrix": matrix,
        "total_capabilities": len(matrix),
    }
