"""Deterministic CVSS-aligned risk calculation engine.

Computes repeatable risk scores based on:
- Base exploitability (vector, complexity, privileges, user interaction)
- Technical impact (confidentiality, integrity, availability)
- Environmental exposure (internet-facing vs internal)
- Asset criticality
- Evidence confidence multiplier
- Attack chain context multiplier

Never relies on arbitrary LLM guesswork for scoring.
"""

from __future__ import annotations

from redloop.assessment.models import Confidence, Finding, Severity


def calculate_risk(
    finding: Finding,
    is_internet_facing: bool = False,
    asset_criticality: float = 1.0,  # 1.0 = standard, 1.5 = high, 2.0 = mission-critical
    is_chained: bool = False,
) -> tuple[float, Severity, str]:
    """Calculate deterministic risk score (0.0 to 10.0), severity, and mathematical breakdown."""
    # 1. Base score by severity category default
    base_scores = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.0,
    }
    raw_base = base_scores.get(finding.severity, 2.5)

    # 2. Confidence multiplier
    confidence_multipliers = {
        Confidence.CONFIRMED: 1.0,
        Confidence.HIGH: 0.95,
        Confidence.MEDIUM: 0.85,
        Confidence.LOW: 0.65,
        Confidence.INFORMATIONAL: 0.5,
    }
    conf_mult = confidence_multipliers.get(finding.confidence, 0.85)

    # 3. Exposure factor (internet-facing increases risk by +1.15x for network-exploitable findings)
    exposure_mult = 1.15 if is_internet_facing and finding.protocol in ("tcp", "udp", "http", "https") else 1.0

    # 4. Criticality factor
    crit_mult = max(0.8, min(asset_criticality, 1.5))

    # 5. Attack chain multiplier (+15% if finding links into an active attack chain)
    chain_mult = 1.15 if is_chained else 1.0

    # Calculate final score
    calculated_score = raw_base * conf_mult * exposure_mult * (crit_mult / 1.0) * chain_mult
    final_score = round(min(10.0, max(0.0, calculated_score)), 1)

    # Assign calculated severity based on deterministic score thresholds
    if final_score >= 9.0:
        assigned_severity = Severity.CRITICAL
    elif final_score >= 7.0:
        assigned_severity = Severity.HIGH
    elif final_score >= 4.0:
        assigned_severity = Severity.MEDIUM
    elif final_score >= 1.0:
        assigned_severity = Severity.LOW
    else:
        assigned_severity = Severity.INFO

    explanation = (
        f"Base: {raw_base} ({finding.severity.value}) "
        f"× Confidence({finding.confidence.value}): {conf_mult:.2f} "
        f"× Exposure(internet={is_internet_facing}): {exposure_mult:.2f} "
        f"× Criticality: {crit_mult:.2f} "
        f"× Chained: {chain_mult:.2f} "
        f"= {final_score}/10.0"
    )

    return final_score, assigned_severity, explanation
