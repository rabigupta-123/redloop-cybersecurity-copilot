"""Null-safe accuracy, confidence, freshness, and calibration metrics.

This module is additive. It does not change the legacy formulas in
``redloop.assessment.evaluation`` that existing callers and tests rely on.
Every metric that is mathematically undefined returns ``None`` together with
an explicit ``NOT_APPLICABLE`` status instead of silently returning ``0.0``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

METRIC_NOT_APPLICABLE = "NOT_APPLICABLE"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
SINGLE_SOURCE = "SINGLE_SOURCE"
HEURISTIC_CONFIDENCE = "HEURISTIC_CONFIDENCE"
NOT_CALIBRATED = "NOT_CALIBRATED"

CONFIDENCE_WEIGHTS: dict[str, float] = {
    "source_reliability": 0.30,
    "source_agreement": 0.20,
    "evidence_integrity": 0.20,
    "freshness": 0.15,
    "provenance_completeness": 0.15,
}

_OPTIONAL_FACTORS = {
    "source_agreement",
    "evidence_integrity",
    "freshness",
    "provenance_completeness",
}


def _clamp(value: float | None) -> float | None:
    if value is None:
        return None
    return max(0.0, min(1.0, float(value)))


def safe_divide(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return float(numerator) / float(denominator)


def calculate_precision_nullable(tp: int, fp: int) -> float | None:
    return safe_divide(tp, tp + fp)


def calculate_recall_nullable(tp: int, fn: int) -> float | None:
    return safe_divide(tp, tp + fn)


def calculate_f1_nullable(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    return safe_divide(2.0 * precision * recall, precision + recall)


def calculate_fpr_nullable(fp: int, tn: int) -> float | None:
    return safe_divide(fp, fp + tn)


def calculate_accuracy_nullable(correct: int, total: int) -> float | None:
    return safe_divide(correct, total)


def build_confusion_matrix(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")
    resolved = list(labels) if labels is not None else sorted(set(y_true) | set(y_pred))
    matrix = {actual: {predicted: 0 for predicted in resolved} for actual in resolved}
    for actual, predicted in zip(y_true, y_pred):
        matrix.setdefault(actual, {key: 0 for key in resolved})
        matrix[actual][predicted] = matrix[actual].get(predicted, 0) + 1
    return {"labels": resolved, "matrix": matrix, "sample_count": len(y_true)}


def classification_metrics(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    labels: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Per-class and aggregate metrics with nulls for undefined denominators."""
    if not y_true or not y_pred:
        return {
            "status": METRIC_NOT_APPLICABLE,
            "reason": "NO_GROUND_TRUTH_SAMPLES",
            "accuracy": None,
            "macro_precision": None,
            "macro_recall": None,
            "macro_f1": None,
            "weighted_f1": None,
            "per_class": {},
            "confusion_matrix": {"labels": [], "matrix": {}, "sample_count": 0},
        }
    confusion = build_confusion_matrix(y_true, y_pred, labels)
    resolved = confusion["labels"]
    matrix = confusion["matrix"]
    total = len(y_true)
    per_class: dict[str, dict[str, Any]] = {}
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []

    for label in resolved:
        tp = matrix.get(label, {}).get(label, 0)
        fp = sum(matrix.get(other, {}).get(label, 0) for other in resolved if other != label)
        fn = sum(
            count for predicted, count in matrix.get(label, {}).items() if predicted != label
        )
        support = tp + fn
        precision = calculate_precision_nullable(tp, fp)
        recall = calculate_recall_nullable(tp, fn)
        f1 = calculate_f1_nullable(precision, recall)
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }
        if precision is not None:
            precisions.append(precision)
        if recall is not None:
            recalls.append(recall)
        if f1 is not None:
            f1s.append(f1)

    def _mean(values: list[float]) -> float | None:
        return (sum(values) / len(values)) if values else None

    weighted_numerator = sum(
        entry["f1"] * entry["support"]
        for entry in per_class.values()
        if entry["f1"] is not None
    )
    weighted_denominator = sum(
        entry["support"] for entry in per_class.values() if entry["f1"] is not None
    )
    correct = sum(1 for actual, predicted in zip(y_true, y_pred) if actual == predicted)

    return {
        "status": "COMPUTED",
        "accuracy": calculate_accuracy_nullable(correct, total),
        "macro_precision": _mean(precisions),
        "macro_recall": _mean(recalls),
        "macro_f1": _mean(f1s),
        "weighted_f1": safe_divide(weighted_numerator, weighted_denominator),
        "per_class": per_class,
        "confusion_matrix": confusion,
    }


@dataclass(frozen=True)
class FreshnessPolicy:
    observation_type: str
    half_life_seconds: float
    description: str = ""


FRESHNESS_POLICIES: dict[str, FreshnessPolicy] = {
    "dns": FreshnessPolicy("dns", 3600.0, "DNS answers and PTR records"),
    "reverse_dns": FreshnessPolicy("reverse_dns", 3600.0, "PTR records"),
    "tls": FreshnessPolicy("tls", 7 * 24 * 3600.0, "TLS certificates"),
    "rdap": FreshnessPolicy("rdap", 30 * 24 * 3600.0, "Registry registration data"),
    "asn": FreshnessPolicy("asn", 30 * 24 * 3600.0, "ASN allocation"),
    "ip": FreshnessPolicy("ip", 24 * 3600.0, "IP classification and routing"),
    "email": FreshnessPolicy("email", 7 * 24 * 3600.0, "Email exposure metadata"),
    "username": FreshnessPolicy("username", 24 * 3600.0, "Public profile presence"),
    "phone": FreshnessPolicy("phone", 30 * 24 * 3600.0, "Numbering plan assignment"),
    "metadata": FreshnessPolicy("metadata", 365 * 24 * 3600.0, "Static file metadata"),
    "default": FreshnessPolicy("default", 3600.0, "Conservative fallback"),
}


def freshness_policy(observation_type: str | None) -> FreshnessPolicy:
    return FRESHNESS_POLICIES.get(
        str(observation_type or "").strip().lower(), FRESHNESS_POLICIES["default"]
    )


def parse_timestamp(value: str | datetime | None) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def calculate_freshness_score(
    observed_at: str | datetime | None,
    half_life_seconds: float,
    now: str | datetime | None = None,
) -> float | None:
    """Return ``2 ** (-age / half_life)`` or ``None`` for malformed inputs."""
    observed = parse_timestamp(observed_at)
    current = parse_timestamp(now) or datetime.now(timezone.utc)
    if observed is None or half_life_seconds is None or half_life_seconds <= 0:
        return None
    age = max(0.0, (current - observed).total_seconds())
    return 2.0 ** (-age / float(half_life_seconds))


def freshness_decay(
    observed_at: str | datetime | None,
    *,
    observation_type: str | None = None,
    half_life_seconds: float | None = None,
    now: str | datetime | None = None,
) -> dict[str, Any]:
    policy = freshness_policy(observation_type)
    half_life = float(half_life_seconds) if half_life_seconds is not None else policy.half_life_seconds
    score = calculate_freshness_score(observed_at, half_life, now)
    observed = parse_timestamp(observed_at)
    current = parse_timestamp(now) or datetime.now(timezone.utc)
    age = max(0.0, (current - observed).total_seconds()) if observed else None
    if score is None:
        return {
            "status": METRIC_NOT_APPLICABLE,
            "reason": "INVALID_OBSERVATION_TIMESTAMP_OR_HALF_LIFE",
            "score": None,
            "half_life_seconds": half_life,
            "observation_type": policy.observation_type,
            "age_seconds": age,
        }
    fresh_window_seconds = max(1.0, half_life * 0.01)
    effective_age = age or 0.0
    return {
        "status": "FRESH" if effective_age <= fresh_window_seconds else "DECAYED",
        "score": round(score, 6),
        "decay_fraction": round(1.0 - score, 6),
        "half_life_seconds": half_life,
        "observation_type": policy.observation_type,
        "age_seconds": round(effective_age, 3),
    }


def _field_value(finding: Any, names: Iterable[str]) -> Any:
    if hasattr(finding, "model_dump"):
        data = finding.model_dump()
    elif hasattr(finding, "to_dict"):
        data = finding.to_dict()
    elif isinstance(finding, Mapping):
        data = dict(finding)
    else:
        data = getattr(finding, "__dict__", {})
    for name in names:
        value = data.get(name)
        if value not in (None, "", [], {}):
            return value
    return None


def assess_provenance(
    finding: Any,
    required_fields: Sequence[str] | None = None,
) -> dict[str, Any]:
    fields = list(required_fields or ("source", "timestamp", "method", "evidence", "confidence"))
    aliases = {
        "source": ("source", "source_or_provider", "provider"),
        "timestamp": ("timestamp", "observation_timestamp", "created_at"),
        "method": ("method", "collection_method", "category"),
        "evidence": ("evidence", "evidence_id", "evidence_ids", "evidence_reference", "evidence_hash"),
        "confidence": ("confidence", "confidence_score"),
    }
    present: list[str] = []
    missing: list[str] = []
    for field_name in fields:
        value = _field_value(finding, aliases.get(field_name, (field_name,)))
        if field_name == "confidence":
            valid = isinstance(value, (int, float)) and 0.0 <= float(value) <= 1.0
        else:
            valid = value is not None
        (present if valid else missing).append(field_name)
    score = (len(present) / len(fields)) if fields else None
    return {
        "status": "COMPLETE" if not missing else "INCOMPLETE",
        "score": round(score, 4) if score is not None else None,
        "required_fields": fields,
        "present_fields": present,
        "missing_fields": missing,
    }


def calculate_source_agreement(
    sources: Sequence[str] | None,
    observations: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Score independent-source agreement without rewarding duplicates."""
    normalized = {
        str(source).strip().lower()
        for source in (sources or [])
        if str(source).strip()
    }
    if not normalized:
        return {"status": METRIC_NOT_APPLICABLE, "score": None, "independent_sources": 0}
    if len(normalized) == 1:
        return {"status": SINGLE_SOURCE, "score": None, "independent_sources": 1}
    if observations:
        counts: dict[str, int] = {}
        for observation in observations:
            key = str(observation)
            counts[key] = counts.get(key, 0) + 1
        majority = max(counts.values())
        score = majority / float(len(observations))
    else:
        score = 0.5
    return {
        "status": "CORROBORATED",
        "score": round(max(0.0, min(1.0, score)), 4),
        "independent_sources": len(normalized),
    }


def compute_finding_confidence(
    *,
    source_reliability: float | None,
    source_agreement: float | None = None,
    independent_source_count: int | None = None,
    evidence_integrity: float | None = None,
    freshness: float | None = None,
    provenance_completeness: float | None = None,
    weights: Mapping[str, float] | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Five-factor evidence confidence using weights 0.30/0.20/0.20/0.15/0.15.

    A single source can never be awarded perfect agreement. If the only
    available evidence is one source and agreement is omitted, agreement is
    scored as 0.0 and the result is labelled ``SINGLE_SOURCE``.
    """
    active_weights = dict(weights or CONFIDENCE_WEIGHTS)
    factors: dict[str, float | None] = {
        "source_reliability": _clamp(source_reliability),
        "source_agreement": _clamp(source_agreement),
        "evidence_integrity": _clamp(evidence_integrity),
        "freshness": _clamp(freshness),
        "provenance_completeness": _clamp(provenance_completeness),
    }
    status = HEURISTIC_CONFIDENCE
    if independent_source_count is not None and independent_source_count <= 1:
        status = SINGLE_SOURCE
        if factors["source_agreement"] is None:
            factors["source_agreement"] = 0.0

    if factors["source_reliability"] is None:
        return {
            "status": INSUFFICIENT_EVIDENCE,
            "label": HEURISTIC_CONFIDENCE,
            "calibration_status": NOT_CALIBRATED,
            "score": None,
            "factors": factors,
            "weights": active_weights,
            "reason": "SOURCE_RELIABILITY_UNAVAILABLE",
        }

    available = {
        name: value for name, value in factors.items() if value is not None
    }
    available_weight = sum(active_weights[name] for name in available)
    if available_weight < 0.5:
        return {
            "status": INSUFFICIENT_EVIDENCE,
            "label": HEURISTIC_CONFIDENCE,
            "calibration_status": NOT_CALIBRATED,
            "score": None,
            "factors": factors,
            "weights": active_weights,
            "reason": "INSUFFICIENT_APPLICABLE_FACTORS",
        }

    normalized_weights = {
        name: round(active_weights[name] / available_weight, 6) for name in available
    }
    score = sum(
        normalized_weights[name] * value for name, value in available.items()
    )
    return {
        "status": status,
        "label": HEURISTIC_CONFIDENCE,
        "calibration_status": NOT_CALIBRATED,
        "score": round(max(0.0, min(1.0, score)), 4),
        "factors": factors,
        "weights": active_weights,
        "normalized_weights": normalized_weights,
        "available_weight": round(available_weight, 4),
        "details": dict(details or {}),
    }


def calculate_brier_score(
    probabilities: Sequence[float],
    outcomes: Sequence[int | bool],
) -> float | None:
    if not probabilities or len(probabilities) != len(outcomes):
        return None
    total = 0.0
    for probability, outcome in zip(probabilities, outcomes):
        p = float(probability)
        if p < 0.0 or p > 1.0:
            return None
        target = 1.0 if bool(outcome) else 0.0
        total += (p - target) ** 2
    return round(total / len(probabilities), 6)


def expected_calibration_error(
    probabilities: Sequence[float],
    outcomes: Sequence[int | bool],
    *,
    bins: int = 10,
    minimum_samples: int = 10,
) -> dict[str, Any]:
    if (
        not probabilities
        or len(probabilities) != len(outcomes)
        or len(probabilities) < minimum_samples
        or bins <= 0
    ):
        return {
            "status": NOT_CALIBRATED,
            "score": None,
            "brier_score": calculate_brier_score(probabilities, outcomes),
            "sample_count": len(probabilities) if probabilities else 0,
            "reason": "INSUFFICIENT_LABELLED_SAMPLES",
            "bins": [],
        }
    buckets: list[dict[str, Any]] = []
    total = len(probabilities)
    error = 0.0
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        members = [
            (float(p), 1.0 if bool(o) else 0.0)
            for p, o in zip(probabilities, outcomes)
            if (lower < p <= upper) or (index == 0 and p == 0.0)
        ]
        if not members:
            continue
        avg_confidence = sum(p for p, _ in members) / len(members)
        accuracy = sum(o for _, o in members) / len(members)
        error += (len(members) / total) * abs(accuracy - avg_confidence)
        buckets.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(members),
                "avg_confidence": round(avg_confidence, 6),
                "accuracy": round(accuracy, 6),
                "gap": round(abs(accuracy - avg_confidence), 6),
            }
        )
    return {
        "status": "COMPUTED" if buckets else NOT_CALIBRATED,
        "calibration_claim": NOT_CALIBRATED,
        "score": round(error, 6) if buckets else None,
        "brier_score": calculate_brier_score(probabilities, outcomes),
        "sample_count": total,
        "bins": buckets,
    }


__all__ = [
    "METRIC_NOT_APPLICABLE",
    "INSUFFICIENT_EVIDENCE",
    "SINGLE_SOURCE",
    "HEURISTIC_CONFIDENCE",
    "NOT_CALIBRATED",
    "CONFIDENCE_WEIGHTS",
    "FRESHNESS_POLICIES",
    "FreshnessPolicy",
    "safe_divide",
    "calculate_precision_nullable",
    "calculate_recall_nullable",
    "calculate_f1_nullable",
    "calculate_fpr_nullable",
    "calculate_accuracy_nullable",
    "build_confusion_matrix",
    "classification_metrics",
    "freshness_policy",
    "parse_timestamp",
    "calculate_freshness_score",
    "freshness_decay",
    "assess_provenance",
    "calculate_source_agreement",
    "compute_finding_confidence",
    "calculate_brier_score",
    "expected_calibration_error",
]
