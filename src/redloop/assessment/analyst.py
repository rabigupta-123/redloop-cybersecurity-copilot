"""AI Security Analyst Layer for RedLoop.

Strictly adheres to:
- Section 35: The AI receives only structured evidence.
- Can: correlate findings, identify attack paths, prioritize remediation,
  explain technical impact, summarize evidence, suggest deterministic tests.
- CANNOT: fabricate evidence, claim exploitation without evidence, override scope,
  change audit history, execute arbitrary code, or silently expand target scope.
- If AI confidence is low or LLM is unavailable, falls back gracefully to deterministic analysis.
"""

from __future__ import annotations

import json
from typing import Any
from pydantic import BaseModel, Field

from redloop.assessment.models import (
    AttackSurfaceGraph,
    Confidence,
    Finding,
    Severity,
)
from redloop.llm import LLMClient


class AIAnalysisResult(BaseModel):
    """Structured output from AI Security Analyst."""

    executive_summary: str
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    remediation_roadmap: list[dict[str, Any]] = Field(default_factory=list)
    suggested_deterministic_tests: list[str] = Field(default_factory=list)
    ai_confidence: Confidence = Confidence.MEDIUM
    is_fallback: bool = False


class AISecurityAnalyst:
    """Safe, structured AI analyst layer that enhances evidence without fabricating findings."""

    def __init__(self, llm_client: LLMClient | None = None):
        self.llm = llm_client or LLMClient()

    def analyze_assessment(
        self,
        target: str,
        findings: list[Finding],
        graph: AttackSurfaceGraph | None = None,
        chains: list[dict[str, Any]] | None = None,
    ) -> AIAnalysisResult:
        """Analyze structured assessment findings and attack paths."""
        if not findings:
            return AIAnalysisResult(
                executive_summary=f"Automated assessment against {target} did not identify any security findings within the authorized scope.",
                ai_confidence=Confidence.HIGH,
                is_fallback=False,
            )

        # Build clean, anonymized structured payload (no raw secrets)
        findings_summary = []
        for f in findings:
            findings_summary.append({
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "port": f.port,
                "endpoint": f.endpoint,
                "description": f.description[:300],
                "risk_score": f.risk_score,
            })

        system_prompt = (
            "You are RedLoop's AI Security Analyst. You analyze ONLY the provided structured security findings.\n"
            "CRITICAL SAFEGUARDS:\n"
            "1. NEVER invent or hallucinate vulnerabilities or evidence not present in the input.\n"
            "2. NEVER claim confirmed exploitation unless finding confidence is CONFIRMED with cryptographic/reproduction proof.\n"
            "3. State confidence explicitly. If evidence is ambiguous, mark confidence as LOW.\n"
            "4. Return strictly valid JSON matching this schema:\n"
            "{\n"
            '  "executive_summary": "1-2 paragraphs highlighting posture and major exposures",\n'
            '  "attack_paths": [{"name": "string", "description": "string", "finding_ids": ["string"]}],\n'
            '  "remediation_roadmap": [{"priority": 1, "action": "string", "finding_ids": ["string"]}],\n'
            '  "suggested_deterministic_tests": ["specific test recommendations"],\n'
            '  "ai_confidence": "HIGH" | "MEDIUM" | "LOW"\n'
            "}"
        )

        user_content = (
            f"Target: {target}\n"
            f"Findings ({len(findings)} total):\n{json.dumps(findings_summary, indent=2)}\n"
            f"Correlated Attack Chains:\n{json.dumps(chains or [], indent=2)}"
        )

        try:
            resp = self.llm.completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.2,
                timeout=25,
            )
            raw_text = resp.text.strip()
            # Clean markdown codeblocks if present
            if raw_text.startswith("```"):
                raw_text = raw_text.split("```")[1]
                if raw_text.startswith("json"):
                    raw_text = raw_text[4:].strip()

            parsed = json.loads(raw_text)
            conf_str = parsed.get("ai_confidence", "MEDIUM").upper()
            ai_conf = getattr(Confidence, conf_str, Confidence.MEDIUM)

            return AIAnalysisResult(
                executive_summary=parsed.get("executive_summary", ""),
                attack_paths=parsed.get("attack_paths", []),
                remediation_roadmap=parsed.get("remediation_roadmap", []),
                suggested_deterministic_tests=parsed.get("suggested_deterministic_tests", []),
                ai_confidence=ai_conf,
                is_fallback=False,
            )

        except Exception:
            # Deterministic Fallback if LLM is offline or times out (never blocks the assessment!)
            return self._deterministic_fallback(target, findings, chains)

    def _deterministic_fallback(
        self,
        target: str,
        findings: list[Finding],
        chains: list[dict[str, Any]] | None = None,
    ) -> AIAnalysisResult:
        """Deterministic rule-based analysis when LLM is unavailable."""
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)

        summary = (
            f"Assessment of {target} identified {len(findings)} findings "
            f"({crit} Critical, {high} High, {med} Medium, {low} Low). "
            f"Immediate remediation should focus on {crit + high} high-severity exposures."
        )

        roadmap = []
        priority = 1
        for f in sorted(findings, key=lambda x: (x.risk_score, x.severity.value), reverse=True):
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                roadmap.append({
                    "priority": priority,
                    "action": f.remediation or f"Remediate {f.title}",
                    "finding_ids": [f.id],
                })
                priority += 1

        attack_paths = []
        if chains:
            for ch in chains:
                attack_paths.append({
                    "name": ch.get("name", "Correlated Vector"),
                    "description": ch.get("description", ""),
                    "finding_ids": ch.get("finding_ids", []),
                })

        suggested = []
        if any(f.port == 80 or f.port == 443 for f in findings):
            suggested.append("Perform deep OpenAPI schema fuzzing if API endpoints are authenticated.")
        if any(f.category == "tls_security" for f in findings):
            suggested.append("Verify certificate renewal and automated cipher hardening.")

        return AIAnalysisResult(
            executive_summary=summary,
            attack_paths=attack_paths,
            remediation_roadmap=roadmap[:10],
            suggested_deterministic_tests=suggested,
            ai_confidence=Confidence.HIGH,
            is_fallback=True,
        )
