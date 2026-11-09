"""Data models and formulas for REDLOOP AI Bug-Bounty Workflow (Phase 3)."""

from __future__ import annotations

from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BountyRunStatus(str, Enum):
    IDLE = "idle"
    STARTING = "starting"
    RECON = "recon"
    PLANNING = "planning"
    VALIDATING = "validating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class FindingValidationState(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNRATED = "unrated"


class EvidenceRecord(BaseModel):
    id: str
    target: str
    endpoint: str
    request: str
    response: str
    response_hash: str
    signature_matched: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CandidateFinding(BaseModel):
    id: str
    title: str
    asset: str
    vuln_class: str  # e.g., CWE-79, CWE-89, CWE-22
    path_pattern: str
    parameter: Optional[str] = None
    state: FindingValidationState = FindingValidationState.CANDIDATE
    severity: SeverityLevel = SeverityLevel.UNRATED
    cvss_score: Optional[float] = None
    confidence: float = 0.0
    priority: float = 0.0
    evidence_ids: List[str] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    reproducibility_rate: float = 0.0  # successes / attempts over 3 runs
    source_reliability: float = 0.8  # 0.0 to 1.0
    fingerprint: Optional[str] = None
    is_duplicate: bool = False

    def compute_fingerprint(self) -> str:
        """SHA-256(normalized host + path pattern + vuln class + parameter)."""
        raw = f"{self.asset.lower().strip()}|{self.path_pattern.strip()}|{self.vuln_class.strip().upper()}|{(self.parameter or '').strip()}"
        fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        self.fingerprint = fp
        return fp

    def calculate_confidence(self) -> float:
        """Confidence C = 0.40·V + 0.25·E + 0.20·R + 0.15·S.
        
        V = 1 if confirmed else 0
        E = min(len(evidence_ids), 3) / 3
        R = reproducibility_rate (0.0 to 1.0)
        S = source_reliability (0.0 to 1.0)
        """
        v = 1.0 if self.state == FindingValidationState.CONFIRMED else 0.0
        e = min(len(self.evidence_ids), 3) / 3.0
        r = max(0.0, min(1.0, self.reproducibility_rate))
        s = max(0.0, min(1.0, self.source_reliability))
        c = (0.40 * v) + (0.25 * e) + (0.20 * r) + (0.15 * s)
        self.confidence = round(c, 4)
        return self.confidence

    def calculate_priority(self, duplicate_probability: float = 0.0) -> float:
        """Priority = C × normalized_severity × (1 − duplicate_probability)."""
        c = self.calculate_confidence()
        # Normalized severity scale 0.0 to 1.0
        severity_weights = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.5,
            SeverityLevel.LOW: 0.2,
            SeverityLevel.INFO: 0.05,
            SeverityLevel.UNRATED: 0.3,
        }
        if self.cvss_score is not None:
            norm_sev = min(10.0, max(0.0, self.cvss_score)) / 10.0
        else:
            norm_sev = severity_weights.get(self.severity, 0.3)

        dup_prob = max(0.0, min(1.0, duplicate_probability))
        p = c * norm_sev * (1.0 - dup_prob)
        self.priority = round(p, 4)
        return self.priority


class ProgramScopeDefinition(BaseModel):
    program_name: str
    policy_url: str
    written_authorization: bool = False
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "HEAD"])
    rate_limit_rps: float = 5.0
    rules: List[str] = Field(default_factory=list)
    signature: Optional[str] = None
    signed_by: Optional[str] = None
    expires_at: Optional[str] = None
    is_active: bool = False

