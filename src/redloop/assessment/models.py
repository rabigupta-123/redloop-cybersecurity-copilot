"""Domain models, schemas, and enums for RedLoop Security Assessment Engine.

Strictly adheres to:
- Common Finding schema (Section 23)
- Evidence integrity with SHA-256 hashes (Section 25)
- Deterministic severity, confidence, and operation classes (Sections 23, 38)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class OperationClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    AUTHENTICATED = "AUTHENTICATED"
    STATE_CHANGING = "STATE_CHANGING"
    DESTRUCTIVE = "DESTRUCTIVE"


class AssessmentDepth(str, Enum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"
    COMPREHENSIVE = "COMPREHENSIVE"


class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


class EvidenceProvenance(str, Enum):
    FRESH = "FRESH"
    HISTORICAL = "HISTORICAL"
    INFERRED = "INFERRED"
    AI_GENERATED = "AI_GENERATED"
    UNAVAILABLE = "UNAVAILABLE"


class ExecutionClass(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    NETWORK_DEPENDENT = "NETWORK_DEPENDENT"
    AI_PROVIDER_DEPENDENT = "AI_PROVIDER_DEPENDENT"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    VERIFIED = "VERIFIED"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Evidence(BaseModel):
    """Structured, verifiable evidence artifact supporting a security finding."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    operation_id: str = "op-default"
    target: str
    provenance: EvidenceProvenance = EvidenceProvenance.FRESH
    source: str = "live_probe"
    source_task_id: str | None = None
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    response_metadata: dict[str, Any] = Field(default_factory=dict)
    response_excerpt: str = ""
    tool_output: str = ""
    parser_result: dict[str, Any] = Field(default_factory=dict)
    sha256_hash: str = ""

    def _hash_preimage(self) -> dict[str, Any]:
        """Return every integrity-relevant field except the digest itself."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "operation_id": self.operation_id,
            "target": self.target,
            "provenance": str(
                self.provenance.value
                if hasattr(self.provenance, "value")
                else self.provenance
            ),
            "source": self.source,
            "source_task_id": self.source_task_id,
            "request": self.request_metadata,
            "response": self.response_metadata,
            "excerpt": self.response_excerpt,
            "tool_output": self.tool_output,
            "parser_result": self.parser_result,
        }

    def compute_hash(self) -> str:
        """Compute the SHA-256 digest over the full canonical pre-image."""
        canonical = json.dumps(
            self._hash_preimage(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Return False when any hashed field was modified after creation."""
        return bool(self.sha256_hash) and self.sha256_hash == self.compute_hash()

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if not self.sha256_hash:
            self.sha256_hash = self.compute_hash()


class Finding(BaseModel):
    """Canonical security finding schema matching Section 23."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(default_factory=lambda: f"RL-{uuid.uuid4().hex[:8].upper()}")
    title: str
    category: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    asset: str
    target: str
    port: int | None = None
    protocol: str = "tcp"
    endpoint: str | None = None
    description: str
    evidence: list[Evidence] = Field(default_factory=list)
    detection_method: str = "deterministic_probe"
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    first_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_operation_id: str = "op-default"
    status: FindingStatus = FindingStatus.OPEN
    cvss_score: float | None = None
    cvss_vector: str | None = None
    risk_score: float = 0.0
    risk_explanation: str = ""


class AssetNode(BaseModel):
    """Node in the attack surface graph (Section 22)."""

    id: str
    type: str  # host | ip | port | service | technology | endpoint | finding
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)


class AssetEdge(BaseModel):
    """Directed relationship in the attack surface graph."""

    source: str
    target: str
    relationship: str  # hosts | exposes | runs | contains | vulnerable_to


class AttackSurfaceGraph(BaseModel):
    """In-memory representation of target attack surface relationships."""

    nodes: list[AssetNode] = Field(default_factory=list)
    edges: list[AssetEdge] = Field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, label: str, **props: Any) -> None:
        if not any(n.id == node_id for n in self.nodes):
            self.nodes.append(
                AssetNode(id=node_id, type=node_type, label=label, properties=props)
            )

    def add_edge(self, source: str, target: str, relationship: str) -> None:
        if not any(
            e.source == source and e.target == target and e.relationship == relationship
            for e in self.edges
        ):
            self.edges.append(
                AssetEdge(source=source, target=target, relationship=relationship)
            )


class StageResult(BaseModel):
    """Execution output of an assessment stage."""

    stage: str
    status: StageStatus
    reason: str = ""
    duration_seconds: float = 0.0
    execution_class: ExecutionClass = ExecutionClass.NETWORK_DEPENDENT
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class AssessmentState(BaseModel):
    """Checkpoint record for persistent assessment resume (Section 30)."""

    id: str = Field(default_factory=lambda: f"asmt-{uuid.uuid4().hex[:12]}")
    target: str
    depth: AssessmentDepth = AssessmentDepth.STANDARD
    status: str = "PENDING"
    current_stage: str = "INIT"
    completed_stages: dict[str, dict[str, Any]] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    graph: AttackSurfaceGraph = Field(default_factory=AttackSurfaceGraph)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
