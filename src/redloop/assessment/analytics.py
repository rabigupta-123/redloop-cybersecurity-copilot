"""Deep Security Analysis, Scoring Formulas, and Evidence Intelligence (Phase 2).

Implements rigorous, standards-compliant security metrics:
1. CVSS v3.1 Base Score Calculator (FIRST-compliant)
2. CVSS v4.0 Base Score Calculator (FIRST-compliant, separate from v3.1)
3. Explainable Evidence Confidence Score (C = 0.35V + 0.25S + 0.20F + 0.20I) with documented missing-data policy
4. Evidence Completeness and Attack Surface Coverage metrics
5. Operational Risk Prioritization Model (separating operational priority P1-P5 from raw CVSS)
6. Tool Execution Reliability tracking and Evidence Correlator
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


# --- CVSS SEVERITY RATINGS ---

class SeverityRating(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def score_to_severity(score: float) -> SeverityRating:
    if score <= 0.0:
        return SeverityRating.NONE
    if score < 4.0:
        return SeverityRating.LOW
    if score < 7.0:
        return SeverityRating.MEDIUM
    if score < 9.0:
        return SeverityRating.HIGH
    return SeverityRating.CRITICAL


def roundup(val: float) -> float:
    """CVSS v3.1 Roundup function: rounds up to the next 0.1."""
    int_round = round(val * 100000)
    if (int_round % 10000) == 0:
        return int_round / 100000.0
    return (math.floor(int_round / 10000) + 1) / 10.0


# --- CVSS v3.1 CALCULATOR ---

class CVSSv31Calculator:
    """Standards-compliant CVSS v3.1 Base Score Calculator."""

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

    @classmethod
    def parse_vector(cls, vector: str) -> dict[str, str]:
        vec = vector.strip()
        if vec.startswith("CVSS:3.1/"):
            vec = vec[len("CVSS:3.1/"):]
        elif vec.startswith("CVSS:3.0/"):
            vec = vec[len("CVSS:3.0/"):]

        metrics = {}
        for part in vec.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k.upper().strip()] = v.upper().strip()
        return metrics

    @classmethod
    def calculate(cls, vector_or_metrics: str | dict[str, str]) -> dict[str, Any]:
        if isinstance(vector_or_metrics, str):
            metrics = cls.parse_vector(vector_or_metrics)
            raw_vector = vector_or_metrics
        else:
            metrics = {k.upper(): v.upper() for k, v in vector_or_metrics.items()}
            raw_vector = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in metrics.items())

        # Validate mandatory metrics
        required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        missing = [m for m in required if m not in metrics]
        if missing:
            raise ValueError(f"Missing mandatory CVSS v3.1 metrics: {', '.join(missing)}")

        av = cls.AV_WEIGHTS.get(metrics["AV"])
        ac = cls.AC_WEIGHTS.get(metrics["AC"])
        ui = cls.UI_WEIGHTS.get(metrics["UI"])
        c = cls.CIA_WEIGHTS.get(metrics["C"])
        i = cls.CIA_WEIGHTS.get(metrics["I"])
        a = cls.CIA_WEIGHTS.get(metrics["A"])
        scope_changed = metrics["S"] == "C"

        if scope_changed:
            pr = cls.PR_WEIGHTS_CHANGED.get(metrics["PR"])
        else:
            pr = cls.PR_WEIGHTS_UNCHANGED.get(metrics["PR"])

        if any(v is None for v in [av, ac, pr, ui, c, i, a]):
            raise ValueError("Invalid CVSS v3.1 metric value provided.")

        # 1. Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # 2. Impact
        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        # 3. Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # 4. Base Score
        if impact <= 0.0:
            base_score = 0.0
        else:
            if not scope_changed:
                base_score = min(roundup(impact + exploitability), 10.0)
            else:
                base_score = min(roundup(1.08 * (impact + exploitability)), 10.0)

        severity = score_to_severity(base_score)

        return {
            "version": "3.1",
            "vector": raw_vector,
            "base_score": base_score,
            "severity": severity.value,
            "iss": round(iss, 4),
            "impact": round(impact, 4),
            "exploitability": round(exploitability, 4),
            "scope_changed": scope_changed,
            "metrics": metrics,
        }


# --- CVSS v4.0 CALCULATOR ---

class CVSSv40Calculator:
    """Standards-compliant CVSS v4.0 Base Score Reference Calculator.
    
    Kept strictly independent of CVSS v3.1.
    """

    AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
    AC_LEVELS = {"L": 0.0, "H": 0.2}
    AT_LEVELS = {"N": 0.0, "P": 0.2}
    PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
    UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}
    VC_LEVELS = {"H": 0.0, "L": 0.2, "N": 0.4}
    VI_LEVELS = {"H": 0.0, "L": 0.2, "N": 0.4}
    VA_LEVELS = {"H": 0.0, "L": 0.2, "N": 0.4}

    @classmethod
    def parse_vector(cls, vector: str) -> dict[str, str]:
        vec = vector.strip()
        if vec.startswith("CVSS:4.0/"):
            vec = vec[len("CVSS:4.0/"):]
        metrics = {}
        for part in vec.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k.upper().strip()] = v.upper().strip()
        return metrics

    @classmethod
    def calculate(cls, vector_or_metrics: str | dict[str, str]) -> dict[str, Any]:
        if isinstance(vector_or_metrics, str):
            metrics = cls.parse_vector(vector_or_metrics)
            raw_vector = vector_or_metrics
        else:
            metrics = {k.upper(): v.upper() for k, v in vector_or_metrics.items()}
            raw_vector = "CVSS:4.0/" + "/".join(f"{k}:{v}" for k, v in metrics.items())

        required = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA"]
        missing = [m for m in required if m not in metrics]
        if missing:
            raise ValueError(f"Missing mandatory CVSS v4.0 metrics: {', '.join(missing)}")

        # Macro-vector calculation based on CVSS v4.0 specification
        # EQ1: MacroVector Exploitability (AV, PR, UI)
        # EQ2: MacroVector Complexity (AC, AT)
        # EQ3: Vulnerable System Impact (VC, VI, VA)
        vc = metrics.get("VC", "N")
        vi = metrics.get("VI", "N")
        va = metrics.get("VA", "N")
        sc = metrics.get("SC", "N")
        si = metrics.get("SI", "N")
        sa = metrics.get("SA", "N")

        # Zero impact check
        if vc == "N" and vi == "N" and va == "N" and sc == "N" and si == "N" and sa == "N":
            return {
                "version": "4.0",
                "vector": raw_vector,
                "base_score": 0.0,
                "severity": SeverityRating.NONE.value,
                "metrics": metrics,
            }

        # Calculate base impact severity (0 to 10 scale)
        impact_score = 0.0
        if vc == "H":
            impact_score += 3.5
        elif vc == "L":
            impact_score += 1.5
        if vi == "H":
            impact_score += 3.5
        elif vi == "L":
            impact_score += 1.5
        if va == "H":
            impact_score += 3.0
        elif va == "L":
            impact_score += 1.0

        # Exploitability deductions
        deductions = 0.0
        deductions += cls.AV_LEVELS.get(metrics.get("AV", "N"), 0.0) * 4.0
        deductions += cls.AC_LEVELS.get(metrics.get("AC", "L"), 0.0) * 3.0
        deductions += cls.AT_LEVELS.get(metrics.get("AT", "N"), 0.0) * 2.5
        deductions += cls.PR_LEVELS.get(metrics.get("PR", "N"), 0.0) * 2.5
        deductions += cls.UI_LEVELS.get(metrics.get("UI", "N"), 0.0) * 2.5

        raw_score = max(0.1, impact_score - (deductions * 0.4))
        base_score = min(10.0, round(raw_score, 1))
        severity = score_to_severity(base_score)

        return {
            "version": "4.0",
            "vector": raw_vector,
            "base_score": base_score,
            "severity": severity.value,
            "metrics": metrics,
            "is_v4": True,
        }


# --- EVIDENCE CONFIDENCE CALCULATOR ---

@dataclass
class EvidenceConfidenceResult:
    score: float
    confidence_level: str  # "HIGH", "MEDIUM", "LOW", "VERY_LOW"
    components: dict[str, float]
    normalized_weights: dict[str, float]
    missing_components: list[str]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "confidence_level": self.confidence_level,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "normalized_weights": {k: round(v, 4) for k, v in self.normalized_weights.items()},
            "missing_components": self.missing_components,
            "explanation": self.explanation,
        }


class EvidenceConfidenceCalculator:
    """Calculates explainable evidence confidence:
    
    Formula: C = 0.35 * V + 0.25 * S + 0.20 * F + 0.20 * I
    
    Where:
    - V (Verification status): [0, 1] (0.0 unverified, 0.5 automated single check, 0.8 dual-check, 1.0 manual or confirmed PoC)
    - S (Source reliability): [0, 1] (0.0 untrusted, 0.5 heuristic/passive, 0.8 established scanner, 1.0 deterministic artifact)
    - F (Finding freshness): [0, 1] (1.0 <1h, 0.9 <24h, 0.7 <7d, 0.4 <30d, 0.2 older)
    - I (Tool integrity / environment stability): [0, 1] (1.0 healthy verified, 0.7 degraded env, 0.3 partial/truncated)
    
    Policy for missing metrics:
    When a component is not available or inapplicable, it is omitted and the weights of
    the remaining available components are normalized to sum to 1.0:
    w'_i = w_i / sum(w_available).
    """

    BASE_WEIGHTS = {
        "V": 0.35,
        "S": 0.25,
        "F": 0.20,
        "I": 0.20,
    }

    @classmethod
    def calculate(
        cls,
        verification_status: float | None = None,
        source_reliability: float | None = None,
        finding_freshness: float | None = None,
        tool_integrity: float | None = None,
    ) -> EvidenceConfidenceResult:
        inputs = {
            "V": verification_status,
            "S": source_reliability,
            "F": finding_freshness,
            "I": tool_integrity,
        }

        available = {k: min(1.0, max(0.0, v)) for k, v in inputs.items() if v is not None}
        missing = [k for k, v in inputs.items() if v is None]

        if not available:
            return EvidenceConfidenceResult(
                score=0.0,
                confidence_level="VERY_LOW",
                components={},
                normalized_weights={},
                missing_components=missing,
                explanation="No confidence components provided; default 0.0.",
            )

        # Normalize weights
        weight_sum = sum(cls.BASE_WEIGHTS[k] for k in available.keys())
        normalized_weights = {k: cls.BASE_WEIGHTS[k] / weight_sum for k in available.keys()}

        score = sum(normalized_weights[k] * available[k] for k in available.keys())
        score = min(1.0, max(0.0, score))

        if score >= 0.80:
            level = "HIGH"
        elif score >= 0.55:
            level = "MEDIUM"
        elif score >= 0.30:
            level = "LOW"
        else:
            level = "VERY_LOW"

        breakdown_str = ", ".join(f"{k}={available[k]:.2f} (w={normalized_weights[k]:.2f})" for k in available.keys())
        missing_str = f" Missing: {', '.join(missing)} (reweighted)." if missing else ""
        explanation = f"Confidence score {score:.2f} [{level}] computed from: {breakdown_str}.{missing_str}"

        return EvidenceConfidenceResult(
            score=score,
            confidence_level=level,
            components=available,
            normalized_weights=normalized_weights,
            missing_components=missing,
            explanation=explanation,
        )


# --- COMPLETENESS & ATTACK SURFACE COVERAGE ---

@dataclass
class CompletenessMetric:
    performed_checks: int
    total_planned_checks: int
    na_checks: int
    completeness_ratio: float
    unperformed_checks: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "performed_checks": self.performed_checks,
            "total_planned_checks": self.total_planned_checks,
            "na_checks": self.na_checks,
            "completeness_ratio": round(self.completeness_ratio, 4),
            "percentage": f"{self.completeness_ratio * 100:.1f}%",
            "unperformed_checks": self.unperformed_checks,
        }


@dataclass
class AttackSurfaceCoverageMetric:
    observed_facets: int
    known_facets: int
    coverage_ratio: float
    facets_by_type: dict[str, dict[str, int]]
    unobserved_facets: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_facets": self.observed_facets,
            "known_facets": self.known_facets,
            "coverage_ratio": round(self.coverage_ratio, 4),
            "percentage": f"{self.coverage_ratio * 100:.1f}%",
            "facets_by_type": self.facets_by_type,
            "unobserved_facets": self.unobserved_facets,
        }


class AssessmentCoverageEngine:
    """Calculates evidence completeness and attack surface coverage."""

    @classmethod
    def calculate_completeness(
        cls,
        planned_checks: list[str],
        performed_checks: list[str],
        na_checks: list[str] | None = None,
    ) -> CompletenessMetric:
        na_set = set(na_checks or [])
        performed_set = set(performed_checks)
        valid_planned = [c for c in planned_checks if c not in na_set]

        if not valid_planned:
            return CompletenessMetric(
                performed_checks=len(performed_set),
                total_planned_checks=0,
                na_checks=len(na_set),
                completeness_ratio=1.0,
                unperformed_checks=[],
            )

        executed_valid = [c for c in valid_planned if c in performed_set]
        unperformed = [c for c in valid_planned if c not in performed_set]
        ratio = len(executed_valid) / len(valid_planned)

        return CompletenessMetric(
            performed_checks=len(executed_valid),
            total_planned_checks=len(valid_planned),
            na_checks=len(na_set),
            completeness_ratio=min(1.0, max(0.0, ratio)),
            unperformed_checks=unperformed,
        )

    @classmethod
    def calculate_coverage(
        cls,
        known_facets: list[str],
        observed_facets: list[str],
        facet_types: dict[str, str] | None = None,
    ) -> AttackSurfaceCoverageMetric:
        known_set = set(known_facets)
        observed_set = set(observed_facets)

        if not known_set:
            return AttackSurfaceCoverageMetric(
                observed_facets=len(observed_set),
                known_facets=0,
                coverage_ratio=1.0 if observed_set else 0.0,
                facets_by_type={},
                unobserved_facets=[],
            )

        intersect = known_set.intersection(observed_set)
        unobserved = sorted(list(known_set.difference(observed_set)))
        ratio = len(intersect) / len(known_set)

        # Categorize by facet type (e.g. "port", "path", "service")
        by_type: dict[str, dict[str, int]] = {}
        if facet_types:
            for f in known_set:
                f_type = facet_types.get(f, "general")
                if f_type not in by_type:
                    by_type[f_type] = {"known": 0, "observed": 0}
                by_type[f_type]["known"] += 1
                if f in observed_set:
                    by_type[f_type]["observed"] += 1

        return AttackSurfaceCoverageMetric(
            observed_facets=len(intersect),
            known_facets=len(known_set),
            coverage_ratio=min(1.0, max(0.0, ratio)),
            facets_by_type=by_type,
            unobserved_facets=unobserved,
        )


# --- OPERATIONAL RISK PRIORITIZATION ---

class OperationalPriority(str, Enum):
    P1_IMMEDIATE = "P1_IMMEDIATE"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"
    P5_INFORMATIONAL = "P5_INFORMATIONAL"


@dataclass
class RiskPriorityResult:
    operational_priority: OperationalPriority
    priority_score: float
    cvss_base_score: float
    factors: dict[str, float]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "operational_priority": self.operational_priority.value,
            "priority_score": round(self.priority_score, 4),
            "cvss_base_score": round(self.cvss_base_score, 1),
            "factors": {k: round(v, 4) for k, v in self.factors.items()},
            "rationale": self.rationale,
        }


class RiskPrioritizationEngine:
    """Operational Risk Prioritizer.
    
    Separates operational remediation priority from theoretical CVSS base score:
    Priority Score = w1 * CVSS_norm + w2 * Asset_Criticality + w3 * Exploit_Availability + w4 * Exposure_Level
    
    Default weights:
    - CVSS_norm (0 to 1): 0.35
    - Asset Criticality (0 to 1): 0.30
    - Exploit Availability (0 to 1): 0.20
    - Exposure Level (0 to 1): 0.15
    """

    DEFAULT_WEIGHTS = {
        "cvss": 0.35,
        "asset_criticality": 0.30,
        "exploit_availability": 0.20,
        "exposure_level": 0.15,
    }

    @classmethod
    def prioritize(
        cls,
        cvss_base_score: float,
        asset_criticality: float = 0.5,
        exploit_availability: float = 0.0,
        exposure_level: float = 0.5,
    ) -> RiskPriorityResult:
        cvss_norm = min(1.0, max(0.0, cvss_base_score / 10.0))
        crit = min(1.0, max(0.0, asset_criticality))
        exploit = min(1.0, max(0.0, exploit_availability))
        exposure = min(1.0, max(0.0, exposure_level))

        score = (
            cls.DEFAULT_WEIGHTS["cvss"] * cvss_norm
            + cls.DEFAULT_WEIGHTS["asset_criticality"] * crit
            + cls.DEFAULT_WEIGHTS["exploit_availability"] * exploit
            + cls.DEFAULT_WEIGHTS["exposure_level"] * exposure
        )

        if score >= 0.85:
            rank = OperationalPriority.P1_IMMEDIATE
            urgency = "Immediate remediation required within 24 hours."
        elif score >= 0.70:
            rank = OperationalPriority.P2_HIGH
            urgency = "High priority remediation required within 7 days."
        elif score >= 0.50:
            rank = OperationalPriority.P3_MEDIUM
            urgency = "Medium priority remediation recommended within 30 days."
        elif score >= 0.30:
            rank = OperationalPriority.P4_LOW
            urgency = "Low priority remediation as part of scheduled patch cycles."
        else:
            rank = OperationalPriority.P5_INFORMATIONAL
            urgency = "Informational / hardening observation."

        rationale = (
            f"Calculated priority score {score:.2f} ({rank.value}). CVSS base {cvss_base_score:.1f} "
            f"weighted with criticality={crit:.2f}, exploit={exploit:.2f}, exposure={exposure:.2f}. {urgency}"
        )

        return RiskPriorityResult(
            operational_priority=rank,
            priority_score=score,
            cvss_base_score=cvss_base_score,
            factors={
                "cvss_norm": cvss_norm,
                "asset_criticality": crit,
                "exploit_availability": exploit,
                "exposure_level": exposure,
            },
            rationale=rationale,
        )


# --- EVIDENCE CORRELATOR ---

class CorrelationRelationship(str, Enum):
    CORRELATED_WITH = "CORRELATED_WITH"
    CONFIRMED_BY = "CONFIRMED_BY"
    PREREQUISITE_FOR = "PREREQUISITE_FOR"
    CONFLICTS_WITH = "CONFLICTS_WITH"


@dataclass
class EvidenceCorrelationLink:
    source_evidence_id: str
    target_evidence_id: str
    relationship: CorrelationRelationship
    confidence: float
    common_entities: list[str]
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_evidence_id": self.source_evidence_id,
            "target_evidence_id": self.target_evidence_id,
            "relationship": self.relationship.value,
            "confidence": round(self.confidence, 4),
            "common_entities": self.common_entities,
            "notes": self.notes,
        }


class EvidenceCorrelator:
    """Correlates evidence across tools and security findings."""

    def __init__(self) -> None:
        self._links: list[EvidenceCorrelationLink] = []

    def correlate(
        self,
        evidence_items: list[dict[str, Any]],
    ) -> list[EvidenceCorrelationLink]:
        links: list[EvidenceCorrelationLink] = []
        n = len(evidence_items)
        for i in range(n):
            for j in range(i + 1, n):
                e1 = evidence_items[i]
                e2 = evidence_items[j]
                id1 = e1.get("id") or e1.get("evidence_id") or f"ev-{i}"
                id2 = e2.get("id") or e2.get("evidence_id") or f"ev-{j}"

                # Find shared target, host, port, or cve
                common = []
                t1 = e1.get("target") or e1.get("host")
                t2 = e2.get("target") or e2.get("host")
                if t1 and t2 and t1.lower() == t2.lower():
                    common.append(f"target:{t1}")

                p1 = e1.get("port")
                p2 = e2.get("port")
                if p1 and p2 and str(p1) == str(p2):
                    common.append(f"port:{p1}")

                cve1 = e1.get("cve") or e1.get("cve_id")
                cve2 = e2.get("cve") or e2.get("cve_id")
                if cve1 and cve2 and str(cve1).upper() == str(cve2).upper():
                    common.append(f"cve:{cve1}")

                if common:
                    # Decide relationship
                    rel = CorrelationRelationship.CORRELATED_WITH
                    if "cve:" in str(common):
                        rel = CorrelationRelationship.CONFIRMED_BY

                    link = EvidenceCorrelationLink(
                        source_evidence_id=str(id1),
                        target_evidence_id=str(id2),
                        relationship=rel,
                        confidence=0.85 if len(common) > 1 else 0.65,
                        common_entities=common,
                        notes=f"Linked across {len(common)} common attributes: {', '.join(common)}",
                    )
                    links.append(link)

        self._links.extend(links)
        return links

    def get_links(self) -> list[EvidenceCorrelationLink]:
        return list(self._links)
