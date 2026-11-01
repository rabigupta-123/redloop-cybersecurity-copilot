"""Evaluation, provenance scoring, confidence modeling, and accuracy metrics for REDLOOP.

Implements Phases 5 & 6:
- Mathematical accuracy metrics (Precision, Recall, F1, FPR, RoutingAccuracy, EvidenceCoverage, ProvenanceCompleteness, WorkflowSuccess)
- Multi-factor transparent confidence scoring
- Explicit verification states (OBSERVED, VERIFIED, INFERRED, UNVERIFIED_LOCALLY, NOT_FOUND_IN_CHECKED_SOURCES, PROVIDER_NOT_CONFIGURED, RATE_LIMITED, FAILED, UNKNOWN)
- Strict boundary: No high confidence inference is ever automatically marked VERIFIED.
- Truthful reporting: No fabricated "AI accuracy" when there is no ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import math
import os
from pathlib import Path
import sqlite3
import time
from typing import Any
import uuid


class VerificationState(str, Enum):
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    UNVERIFIED_LOCALLY = "UNVERIFIED_LOCALLY"
    NOT_FOUND_IN_CHECKED_SOURCES = "NOT_FOUND_IN_CHECKED_SOURCES"
    PROVIDER_NOT_CONFIGURED = "PROVIDER_NOT_CONFIGURED"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class OllamaHealthState(str, Enum):
    OLLAMA_AVAILABLE = "OLLAMA_AVAILABLE"
    OLLAMA_UNAVAILABLE = "OLLAMA_UNAVAILABLE"
    OLLAMA_STARTING = "OLLAMA_STARTING"
    OLLAMA_MODEL_MISSING = "OLLAMA_MODEL_MISSING"
    OLLAMA_INFERENCE_READY = "OLLAMA_INFERENCE_READY"
    OLLAMA_ERROR = "OLLAMA_ERROR"


class ProviderState(str, Enum):
    CONFIGURED = "CONFIGURED"
    REACHABLE = "REACHABLE"
    INFERENCE_READY = "INFERENCE_READY"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


# ---------------------------------------------------------------------------
# MATHEMATICAL ACCURACY FORMULAS (Ground-truth datasets only)
# ---------------------------------------------------------------------------

def calculate_precision(tp: int, fp: int) -> float:
    """Precision = TP / (TP + FP). Measures how many reported findings are actually correct."""
    total = tp + fp
    if total <= 0:
        return 0.0
    return round(float(tp) / float(total), 4)


def calculate_recall(tp: int, fn: int) -> float:
    """Recall = TP / (TP + FN). Measures how many known findings REDLOOP successfully detected."""
    total = tp + fn
    if total <= 0:
        return 0.0
    return round(float(tp) / float(total), 4)


def calculate_f1(precision: float, recall: float) -> float:
    """F1 = 2 * (Precision * Recall) / (Precision + Recall). Harmonic mean of precision and recall."""
    denom = precision + recall
    if denom <= 0.0:
        return 0.0
    return round(2.0 * (precision * recall) / denom, 4)


def calculate_fpr(fp: int, tn: int) -> float:
    """FPR = FP / (FP + TN). False positive rate."""
    total = fp + tn
    if total <= 0:
        return 0.0
    return round(float(fp) / float(total), 4)


def calculate_routing_accuracy(correctly_routed: int, total_requests: int) -> float:
    """RoutingAccuracy = CorrectlyRoutedRequests / TotalRequests."""
    if total_requests <= 0:
        return 0.0
    return round(float(correctly_routed) / float(total_requests), 4)


def calculate_evidence_coverage(
    findings_with_evidence: int | None = None,
    total_findings: int = 0,
    findings_with_valid_evidence: int | None = None,
) -> float:
    """EvidenceCoverage = (FindingsWithValidEvidence / TotalFindings) * 100."""
    with_ev = findings_with_valid_evidence if findings_with_valid_evidence is not None else (findings_with_evidence or 0)
    if total_findings <= 0:
        return 100.0  # Zero findings trivially has full coverage
    return round((float(with_ev) / float(total_findings)) * 100.0, 2)


def calculate_workflow_success(successful_workflows: int, total_workflows: int) -> float:
    """WorkflowSuccess = (SuccessfulCompleteWorkflows / TotalWorkflows) * 100."""
    if total_workflows <= 0:
        return 0.0
    return round((float(successful_workflows) / float(total_workflows)) * 100.0, 2)


def calculate_provenance_completeness(finding: dict[str, Any] | Any) -> float:
    """Provenance Completeness: PC = (source + timestamp + method + evidence + confidence) / 5.
    
    For each finding, all 5 fields are evaluated:
    - source
    - timestamp
    - method
    - evidence (or evidence reference / evidence_id)
    - confidence (valid float between 0.0 and 1.0)
    """
    if hasattr(finding, "to_dict"):
        data = finding.to_dict()
    elif hasattr(finding, "model_dump"):
        data = finding.model_dump()
    elif isinstance(finding, dict):
        data = finding
    else:
        data = getattr(finding, "__dict__", {})

    has_source = bool(data.get("source") or data.get("source_or_provider") or data.get("provider"))
    has_timestamp = bool(data.get("timestamp") or data.get("observation_timestamp") or data.get("created_at"))
    has_method = bool(data.get("method") or data.get("collection_method") or data.get("category"))
    has_evidence = bool(
        data.get("evidence")
        or data.get("evidence_id")
        or data.get("evidence_ids")
        or data.get("evidence_reference")
        or data.get("evidence_hash")
    )
    conf = data.get("confidence")
    has_confidence = conf is not None and isinstance(conf, (int, float)) and 0.0 <= float(conf) <= 1.0

    score = (
        (1.0 if has_source else 0.0)
        + (1.0 if has_timestamp else 0.0)
        + (1.0 if has_method else 0.0)
        + (1.0 if has_evidence else 0.0)
        + (1.0 if has_confidence else 0.0)
    ) / 5.0

    return round(score, 4)


# ---------------------------------------------------------------------------
# TRANSPARENT CONFIDENCE MODEL
# ---------------------------------------------------------------------------

@dataclass
class ConfidenceFactors:
    source_reliability: float = 0.8       # Weight 0.25 (S)
    direct_observation: float = 0.9       # Weight 0.25 (D)
    independent_corroboration: float = 0.5 # Weight 0.20 (I)
    freshness: float = 1.0                # Weight 0.10 (F)
    parser_validation: float = 1.0        # Weight 0.10 (P)
    cross_source_consistency: float = 0.8 # Weight 0.10 (X)


_CONFIDENCE_WEIGHTS = {
    "source_reliability": 0.25,
    "direct_observation": 0.25,
    "independent_corroboration": 0.20,
    "freshness": 0.10,
    "parser_validation": 0.10,
    "cross_source_consistency": 0.10,
}


def calculate_confidence(
    factors: ConfidenceFactors | None = None,
    *,
    source_reliability: float = 0.8,
    direct_observation: float = 0.9,
    independent_corroboration: float = 0.5,
    freshness: float = 1.0,
    parser_validation: float = 1.0,
    cross_source_consistency: float = 0.8,
    not_applicable_factors: set[str] | None = None,
) -> float:
    """Calculate transparent confidence score:
    C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X, normalized to 0.0 - 1.0.

    Factors whose measurement is not applicable (for example independent
    corroboration for a loopback address that has no external sources) can be
    excluded. Remaining weights are renormalized so absence of an applicable
    check is not silently scored as a zero.
    """
    if factors is not None:
        s = factors.source_reliability
        d = factors.direct_observation
        i = factors.independent_corroboration
        f = factors.freshness
        p = factors.parser_validation
        x = factors.cross_source_consistency
    else:
        s = source_reliability
        d = direct_observation
        i = independent_corroboration
        f = freshness
        p = parser_validation
        x = cross_source_consistency

    # Clamp all inputs to [0.0, 1.0]
    values = {
        "source_reliability": max(0.0, min(1.0, float(s))),
        "direct_observation": max(0.0, min(1.0, float(d))),
        "independent_corroboration": max(0.0, min(1.0, float(i))),
        "freshness": max(0.0, min(1.0, float(f))),
        "parser_validation": max(0.0, min(1.0, float(p))),
        "cross_source_consistency": max(0.0, min(1.0, float(x))),
    }

    excluded = set(not_applicable_factors or ())
    unknown = excluded - set(_CONFIDENCE_WEIGHTS)
    if unknown:
        raise ValueError(f"Unknown confidence factors: {sorted(unknown)}")
    total_weight = sum(
        weight for name, weight in _CONFIDENCE_WEIGHTS.items() if name not in excluded
    )
    if total_weight <= 0.0:
        return 0.0
    score = sum(
        _CONFIDENCE_WEIGHTS[name] * value
        for name, value in values.items()
        if name not in excluded
    ) / total_weight

    return round(max(0.0, min(1.0, score)), 4)


def resolve_verification_state(
    confidence: float,
    directly_observed: bool,
    provider_configured: bool = True,
    rate_limited: bool = False,
    call_failed: bool = False,
    is_inference: bool = False,
) -> VerificationState:
    """Determine explicit verification state.
    
    CRITICAL RULE: A high confidence inference must NEVER automatically become VERIFIED.
    """
    if not provider_configured:
        return VerificationState.PROVIDER_NOT_CONFIGURED
    if rate_limited:
        return VerificationState.RATE_LIMITED
    if call_failed:
        return VerificationState.FAILED
    if is_inference:
        return VerificationState.INFERRED
    if directly_observed and confidence >= 0.90:
        return VerificationState.VERIFIED
    if directly_observed:
        return VerificationState.OBSERVED
    return VerificationState.UNVERIFIED_LOCALLY


# ---------------------------------------------------------------------------
# OFFLINE MODE AND OLLAMA DETECTION
# ---------------------------------------------------------------------------

def is_offline_mode() -> bool:
    """Check if REDLOOP is configured in strict offline mode (OFFLINE_MODE=true)."""
    val = os.environ.get("OFFLINE_MODE", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def check_ollama_health(host: str = "127.0.0.1", port: int = 11434, timeout: float = 0.5) -> dict[str, Any]:
    """Inspect local Ollama daemon state without blocking."""
    import socket
    status = OllamaHealthState.OLLAMA_UNAVAILABLE
    models: list[str] = []
    error = None

    try:
        with socket.create_connection((host, port), timeout=timeout):
            status = OllamaHealthState.OLLAMA_AVAILABLE
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return {
            "status": OllamaHealthState.OLLAMA_UNAVAILABLE.value,
            "ready": False,
            "models": [],
            "error": str(e),
            "cloud_fallback_available": True,
        }

    # Query tags if available
    try:
        import httpx
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"http://{host}:{port}/api/tags")
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                if models:
                    status = OllamaHealthState.OLLAMA_INFERENCE_READY
                else:
                    status = OllamaHealthState.OLLAMA_MODEL_MISSING
            else:
                status = OllamaHealthState.OLLAMA_ERROR
    except Exception as exc:
        error = str(exc)

    return {
        "status": status.value,
        "ready": status == OllamaHealthState.OLLAMA_INFERENCE_READY,
        "models": models,
        "error": error,
        "cloud_fallback_available": True,
    }


# ---------------------------------------------------------------------------
# INTENT ROUTING EVALUATION PIPELINE & CONFUSION MATRIX
# ---------------------------------------------------------------------------

def evaluate_intent_routing(
    prompts: list[dict[str, Any]] | str | Path,
    orchestrator: Any = None,
) -> dict[str, Any]:
    """Evaluate intent routing accuracy against ground-truth prompts.

    Computes:
    - Overall RoutingAccuracy = CorrectlyRouted / TotalRequests
    - Confusion Matrix (expected x predicted)
    - Per-intent TP, FP, FN, TN, Precision, Recall, F1, and FPR
    - List of misclassifications for triage
    """
    if isinstance(prompts, (str, Path)):
        p_path = Path(prompts)
        if not p_path.is_absolute():
            p_path = Path.cwd() / p_path
        with open(p_path, "r", encoding="utf-8") as f:
            items: list[dict[str, Any]] = json.load(f)
    else:
        items = list(prompts)

    if orchestrator is None:
        from redloop.assessment.orchestrator import TaskOrchestrator
        orchestrator = TaskOrchestrator()

    total_prompts = len(items)
    if total_prompts == 0:
        return {
            "total_prompts": 0,
            "correctly_routed": 0,
            "routing_accuracy": 0.0,
            "per_intent_metrics": {},
            "confusion_matrix": {},
            "misclassifications": [],
        }

    all_expected = [item.get("expected_intent", "") for item in items]
    observed_preds: list[str] = []
    misclassifications: list[dict[str, Any]] = []
    correctly_routed = 0

    # Execute classifications
    for item in items:
        p_text = item.get("prompt", "")
        expected = item.get("expected_intent", "")
        context = item.get("context")
        res = orchestrator.parse_intent(p_text, context=context)
        pred = res.get("intent", "UNKNOWN")
        observed_preds.append(pred)

        if pred == expected:
            correctly_routed += 1
        else:
            misclassifications.append({
                "id": item.get("id"),
                "prompt": p_text,
                "expected": expected,
                "predicted": pred,
                "category": item.get("category", "general"),
                "confidence": res.get("confidence", 0.0),
            })

    # Build unique intent vocabulary
    unique_intents = sorted(set(all_expected + observed_preds))

    # Confusion matrix: confusion_matrix[expected][predicted]
    confusion_matrix: dict[str, dict[str, int]] = {
        exp: {pred: 0 for pred in unique_intents} for exp in unique_intents
    }
    for exp, pred in zip(all_expected, observed_preds):
        confusion_matrix[exp][pred] += 1

    # Per-intent metrics (TP, FP, FN, TN, Precision, Recall, F1, FPR)
    per_intent_metrics: dict[str, dict[str, Any]] = {}
    for intent_name in unique_intents:
        tp = sum(1 for exp, pred in zip(all_expected, observed_preds) if exp == intent_name and pred == intent_name)
        fp = sum(1 for exp, pred in zip(all_expected, observed_preds) if exp != intent_name and pred == intent_name)
        fn = sum(1 for exp, pred in zip(all_expected, observed_preds) if exp == intent_name and pred != intent_name)
        tn = sum(1 for exp, pred in zip(all_expected, observed_preds) if exp != intent_name and pred != intent_name)

        prec = calculate_precision(tp, fp)
        rec = calculate_recall(tp, fn)
        f1_score = calculate_f1(prec, rec)
        fpr = calculate_fpr(fp, tn)

        per_intent_metrics[intent_name] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": prec,
            "recall": rec,
            "f1": f1_score,
            "fpr": fpr,
            "support": tp + fn,
        }

    routing_accuracy = calculate_routing_accuracy(correctly_routed, total_prompts)

    return {
        "total_prompts": total_prompts,
        "correctly_routed": correctly_routed,
        "routing_accuracy": routing_accuracy,
        "per_intent_metrics": per_intent_metrics,
        "confusion_matrix": confusion_matrix,
        "misclassifications": misclassifications,
    }


# ---------------------------------------------------------------------------
# LOW-CONFIDENCE REVIEW QUEUE
# ---------------------------------------------------------------------------

class LowConfidenceReviewQueue:
    """Persistent storage and review queue for sub-threshold confidence inferences & intent routes."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = Path("data/confidence_review.sqlite")
        self.db_path = Path(db_path)
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
        except Exception:
            self.db_path = Path(":memory:")
            self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS low_confidence_reviews (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    item_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    prompt_or_summary TEXT NOT NULL,
                    classified_as TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    factors_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
                    resolution_notes TEXT DEFAULT '',
                    reviewed_by TEXT DEFAULT '',
                    reviewed_at TEXT DEFAULT ''
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lcr_status ON low_confidence_reviews(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_lcr_conf ON low_confidence_reviews(confidence)")
            conn.commit()

    def add(
        self,
        item_type: str,
        prompt_or_summary: str,
        classified_as: str,
        confidence: float,
        target: str = "",
        factors: dict[str, Any] | None = None,
        id: str | None = None,
    ) -> str:
        review_id = id or f"lcr-{uuid.uuid4().hex[:8]}"
        created_at = datetime.now(timezone.utc).isoformat()
        factors_json = json.dumps(factors or {})
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO low_confidence_reviews
                (id, created_at, item_type, target, prompt_or_summary, classified_as, confidence, factors_json, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_REVIEW')
                """,
                (review_id, created_at, item_type, target, prompt_or_summary, classified_as, float(confidence), factors_json),
            )
            conn.commit()
        return review_id

    def list_items(self, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self._get_conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM low_confidence_reviews WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM low_confidence_reviews ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["factors"] = json.loads(d.get("factors_json") or "{}")
            except Exception:
                d["factors"] = {}
            result.append(d)
        return result

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM low_confidence_reviews WHERE id = ?", (item_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["factors"] = json.loads(d.get("factors_json") or "{}")
            except Exception:
                d["factors"] = {}
            return d

    def resolve(
        self,
        item_id: str,
        status: str,
        reviewed_by: str = "operator",
        notes: str = "",
    ) -> bool:
        reviewed_at = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            cur = conn.execute(
                """
                UPDATE low_confidence_reviews
                SET status = ?, resolution_notes = ?, reviewed_by = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (status, notes, reviewed_by, reviewed_at, item_id),
            )
            conn.commit()
            return cur.rowcount > 0

    def get_summary(self) -> dict[str, Any]:
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM low_confidence_reviews").fetchone()[0]
            pending = conn.execute("SELECT COUNT(*) FROM low_confidence_reviews WHERE status = 'PENDING_REVIEW'").fetchone()[0]
            reviewed = total - pending
            avg_conf_row = conn.execute("SELECT AVG(confidence) FROM low_confidence_reviews").fetchone()[0]
            avg_conf = round(float(avg_conf_row or 0.0), 3)
        return {
            "total_items": total,
            "pending_review": pending,
            "reviewed": reviewed,
            "average_confidence": avg_conf,
        }


_GLOBAL_REVIEW_QUEUE: LowConfidenceReviewQueue | None = None


def get_review_queue(db_path: str | Path | None = None) -> LowConfidenceReviewQueue:
    global _GLOBAL_REVIEW_QUEUE
    if _GLOBAL_REVIEW_QUEUE is None or db_path is not None:
        _GLOBAL_REVIEW_QUEUE = LowConfidenceReviewQueue(db_path=db_path)
    return _GLOBAL_REVIEW_QUEUE
