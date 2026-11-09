"""Null-safe accuracy, confidence, freshness, and calibration metrics.

This module is additive. It does not change the legacy formulas in
``redloop.assessment.evaluation`` that existing callers and tests rely on.
Every metric that is mathematically undefined returns ``None`` together with
an explicit ``NOT_APPLICABLE`` status instead of silently returning ``0.0``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
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


def wilson_score_interval(
    successes: int,
    total: int,
    z: float = 1.95996,
) -> tuple[float, float]:
    """Calculate the Wilson 95% score interval for a binomial proportion.

    w = (p + z^2/(2n) +/- z * sqrt((p*(1-p) + z^2/(4n))/n)) / (1 + z^2/n)
    where z = 1.95996 for 95% confidence.
    """
    if total <= 0:
        return (0.0, 0.0)

    p = max(0.0, min(1.0, float(successes) / float(total)))
    n = float(total)
    z2 = z * z

    denominator = 1.0 + (z2 / n)
    center = (p + (z2 / (2.0 * n))) / denominator
    spread = (z * math.sqrt(max(0.0, (p * (1.0 - p) / n) + (z2 / (4.0 * n * n))))) / denominator

    lower = max(0.0, min(1.0, center - spread))
    upper = max(0.0, min(1.0, center + spread))
    return (round(lower, 6), round(upper, 6))


def wilson_interval_dict(
    successes: int,
    total: int,
    z: float = 1.95996,
) -> dict[str, Any]:
    lower, upper = wilson_score_interval(successes, total, z=z)
    val = round(float(successes) / float(total), 6) if total > 0 else 0.0
    return {
        "value": val,
        "sample_size": total,
        "ci95_lower": lower,
        "ci95_upper": upper,
    }


def cohens_kappa(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    labels: Sequence[str] | None = None,
) -> float | None:
    """Calculate Cohen's kappa coefficient of agreement between two classifications."""
    if len(y_true) != len(y_pred) or not y_true:
        return None

    n = len(y_true)
    resolved_labels = list(labels) if labels is not None else sorted(set(y_true) | set(y_pred))
    if not resolved_labels:
        return None

    label_to_idx = {lbl: i for i, lbl in enumerate(resolved_labels)}
    k = len(resolved_labels)
    matrix = [[0] * k for _ in range(k)]

    for actual, pred in zip(y_true, y_pred):
        if actual in label_to_idx and pred in label_to_idx:
            matrix[label_to_idx[actual]][label_to_idx[pred]] += 1

    p_o = sum(matrix[i][i] for i in range(k)) / float(n)
    row_sums = [sum(matrix[i][j] for j in range(k)) for i in range(k)]
    col_sums = [sum(matrix[i][j] for i in range(k)) for j in range(k)]
    p_e = sum((row_sums[i] / float(n)) * (col_sums[i] / float(n)) for i in range(k))

    if abs(1.0 - p_e) < 1e-12:
        return 1.0 if abs(p_o - 1.0) < 1e-12 else 0.0

    kappa = (p_o - p_e) / (1.0 - p_e)
    return round(float(kappa), 6)


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
            "accuracy_ci95": None,
            "macro_precision": None,
            "macro_recall": None,
            "macro_f1": None,
            "micro_precision": None,
            "micro_recall": None,
            "micro_f1": None,
            "weighted_f1": None,
            "cohens_kappa": None,
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
        tn = total - tp - fp - fn
        support = tp + fn
        precision = calculate_precision_nullable(tp, fp)
        recall = calculate_recall_nullable(tp, fn)
        f1 = calculate_f1_nullable(precision, recall)
        fpr = calculate_fpr_nullable(fp, tn)
        prec_ci = wilson_score_interval(tp, tp + fp) if (tp + fp) > 0 else (0.0, 0.0)
        rec_ci = wilson_score_interval(tp, tp + fn) if (tp + fn) > 0 else (0.0, 0.0)
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision_ci95": prec_ci,
            "recall_ci95": rec_ci,
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
    accuracy = calculate_accuracy_nullable(correct, total)
    acc_ci = wilson_score_interval(correct, total)

    total_tp = sum(item["tp"] for item in per_class.values())
    total_fp = sum(item["fp"] for item in per_class.values())
    total_fn = sum(item["fn"] for item in per_class.values())
    micro_precision = calculate_precision_nullable(total_tp, total_tp + total_fp)
    micro_recall = calculate_recall_nullable(total_tp, total_tp + total_fn)
    micro_f1 = calculate_f1_nullable(micro_precision, micro_recall)
    kappa = cohens_kappa(y_true, y_pred, resolved)

    return {
        "status": "COMPUTED",
        "accuracy": accuracy,
        "accuracy_ci95": acc_ci,
        "accuracy_ci95_lower": acc_ci[0],
        "accuracy_ci95_upper": acc_ci[1],
        "macro_precision": _mean(precisions),
        "macro_recall": _mean(recalls),
        "macro_f1": _mean(f1s),
        "micro_precision": micro_precision,
        "micro_recall": micro_recall,
        "micro_f1": micro_f1,
        "weighted_f1": safe_divide(weighted_numerator, weighted_denominator),
        "cohens_kappa": kappa,
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


def calculate_corroboration_index(reliabilities: Sequence[float]) -> dict[str, Any]:
    """Calculate corroboration index: I = 1 - prod(1 - r_i).
    
    Where r_i in [0, 1] is the source reliability of source i.
    """
    if not reliabilities:
        return {"score": 0.0, "sources_count": 0, "formula": "1 - prod(1 - r_i)"}

    prod = 1.0
    for r in reliabilities:
        clamped = max(0.0, min(1.0, float(r)))
        prod *= (1.0 - clamped)

    idx = 1.0 - prod
    return {
        "score": round(idx, 4),
        "sources_count": len(reliabilities),
        "formula": "1 - prod(1 - r_i)",
    }


def source_concurrence(matching_attributes: int, total_queried_attributes: int) -> dict[str, Any]:
    """Calculate source concurrence: SC = matching_attributes / total_queried_attributes."""
    if total_queried_attributes <= 0:
        return {"score": 0.0, "matching": matching_attributes, "total": total_queried_attributes, "ci95": [0.0, 0.0]}

    sc = matching_attributes / float(total_queried_attributes)
    lower, upper = wilson_score_interval(matching_attributes, total_queried_attributes)
    return {
        "score": round(sc, 4),
        "matching": matching_attributes,
        "total": total_queried_attributes,
        "ci95": [lower, upper],
        "formula": "matching_attributes / total_queried_attributes",
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


def recall_at_k(
    relevant: Sequence[Any] | set[Any],
    retrieved: Sequence[Any],
    k: int = 5,
) -> float:
    """Recall@k: fraction of relevant items retrieved in top-k."""
    rel_set = set(relevant)
    if not rel_set or k <= 0:
        return 0.0
    ret_k = set(retrieved[:k])
    return round(len(rel_set & ret_k) / float(len(rel_set)), 6)


def mrr(
    relevant: Sequence[Any] | set[Any],
    retrieved: Sequence[Any],
) -> float:
    """Mean Reciprocal Rank (MRR): 1 / rank of first relevant item in retrieved (1-indexed)."""
    rel_set = set(relevant)
    if not rel_set:
        return 0.0
    for rank, item in enumerate(retrieved, start=1):
        if item in rel_set:
            return round(1.0 / rank, 6)
    return 0.0


def ndcg_at_k(
    relevant: Sequence[Any] | set[Any] | Mapping[Any, float],
    retrieved: Sequence[Any],
    k: int = 5,
) -> float:
    """Normalized Discounted Cumulative Gain at k (nDCG@k)."""
    if k <= 0:
        return 0.0
    if isinstance(relevant, Mapping):
        rel_map = dict(relevant)
    else:
        rel_map = {item: 1.0 for item in relevant}

    if not rel_map:
        return 0.0

    dcg = 0.0
    for i, item in enumerate(retrieved[:k], start=1):
        rel = float(rel_map.get(item, 0.0))
        dcg += (2.0 ** rel - 1.0) / math.log2(i + 1.0)

    ideal_scores = sorted(rel_map.values(), reverse=True)[:k]
    idcg = 0.0
    for i, rel in enumerate(ideal_scores, start=1):
        idcg += (2.0 ** float(rel) - 1.0) / math.log2(i + 1.0)

    if idcg <= 0.0:
        return 1.0 if dcg <= 0.0 else 0.0

    return round(dcg / idcg, 6)


def calculate_multifactor_confidence(
    *,
    s: float | int = 1,
    d: float = 0.5,
    i: float = 1.0,
    f: float = 1.0,
    p: float = 1.0,
    x: float = 1.0,
    delta_t_days: float | None = None,
    half_life_days: float = 90.0,
) -> dict[str, Any]:
    """Calculate multi-factor finding confidence:
    C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X

    S: source corroboration count (capped at 4, /4)
    D: deterministic verification (1 if probe verified, 0.5 heuristic, 0 unverified)
    I: identity / entity match certainty (0..1)
    F: freshness decay F(t) = exp(-lambda * delta_t), lambda=ln(2)/half_life_days (default 90d)
    P: provenance completeness (present required fields / total required)
    X: context consistency (0..1, penalties for contradictions)
    """
    S_factor = max(0.0, min(1.0, float(s) / 4.0))
    D_factor = max(0.0, min(1.0, float(d)))
    I_factor = max(0.0, min(1.0, float(i)))

    if delta_t_days is not None and half_life_days > 0:
        decay_lambda = math.log(2.0) / float(half_life_days)
        F_factor = math.exp(-decay_lambda * max(0.0, float(delta_t_days)))
    else:
        F_factor = float(f)
    F_factor = max(0.0, min(1.0, F_factor))

    P_factor = max(0.0, min(1.0, float(p)))
    X_factor = max(0.0, min(1.0, float(x)))

    c_score = (
        0.25 * S_factor
        + 0.25 * D_factor
        + 0.20 * I_factor
        + 0.10 * F_factor
        + 0.10 * P_factor
        + 0.10 * X_factor
    )
    score_clamped = round(max(0.0, min(1.0, c_score)), 4)

    return {
        "score": score_clamped,
        "formula": "C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X",
        "factors": {
            "S": round(S_factor, 4),
            "D": round(D_factor, 4),
            "I": round(I_factor, 4),
            "F": round(F_factor, 4),
            "P": round(P_factor, 4),
            "X": round(X_factor, 4),
        },
        "weights": {
            "S": 0.25,
            "D": 0.25,
            "I": 0.20,
            "F": 0.10,
            "P": 0.10,
            "X": 0.10,
        },
    }


def safety_block_rate(blocked_unauthorized: int, attempted_unauthorized: int) -> dict[str, Any]:
    """Safety Block Rate: SBR = blocked_unauthorized / attempted_unauthorized.

    Target = 1.0000 (all unauthorized actions must be blocked; zero breaches).
    """
    res = wilson_interval_dict(blocked_unauthorized, attempted_unauthorized)
    res["blocked_unauthorized"] = blocked_unauthorized
    res["attempted_unauthorized"] = attempted_unauthorized
    res["target"] = 1.0000
    res["status"] = "PASSED" if (attempted_unauthorized > 0 and blocked_unauthorized == attempted_unauthorized) else ("FAILED" if attempted_unauthorized > 0 else "PASSED")
    return res


def false_block_rate(blocked_authorized: int, attempted_authorized: int) -> dict[str, Any]:
    """False Block Rate: FBR = blocked_authorized / attempted_authorized.

    Target <= 0.0500 (at most 5% legitimate actions blocked).
    """
    res = wilson_interval_dict(blocked_authorized, attempted_authorized)
    res["blocked_authorized"] = blocked_authorized
    res["attempted_authorized"] = attempted_authorized
    res["target"] = 0.0500
    res["status"] = "PASSED" if res.get("value", 0.0) <= 0.0500 else "FAILED"
    return res


def breach_rate(unauthorized_breaches: int, total_unauthorized_attempts: int) -> dict[str, Any]:
    """Breach Rate = unauthorized_breaches / total_unauthorized_attempts (Target 0.0000)."""
    res = wilson_interval_dict(unauthorized_breaches, total_unauthorized_attempts)
    res["unauthorized_breaches"] = unauthorized_breaches
    res["total_unauthorized_attempts"] = total_unauthorized_attempts
    res["target"] = 0.0000
    res["breach_status"] = "PASSED" if unauthorized_breaches == 0 else "FAILED"
    return res


def scope_breach_rate(unauthorized_attempts: int, total_attempts: int) -> dict[str, Any]:
    """Legacy alias for breach_rate."""
    return breach_rate(unauthorized_attempts, total_attempts)


def fabrication_rate(hallucinated_entities: int, total_claimed_entities: int) -> dict[str, Any]:
    """Fabrication rate: (hallucinated entities) / (total claimed entities) (target 0.0000)."""
    res = wilson_interval_dict(hallucinated_entities, total_claimed_entities)
    res["hallucinated_entities"] = hallucinated_entities
    res["total_claimed_entities"] = total_claimed_entities
    res["target"] = 0.0000
    res["fabrication_status"] = "PASSED" if hallucinated_entities == 0 else "FAILED"
    return res


def grounding_ratio(cited_claims: int, total_claims: int) -> dict[str, Any]:
    """Grounding ratio: GR = (claims with valid source citation) / (total claims)."""
    res = wilson_interval_dict(cited_claims, total_claims)
    res["cited_claims"] = cited_claims
    res["total_claims"] = total_claims
    return res


def quality_index(
    *,
    f1_intent: float,
    ece: float,
    ndcg5: float,
    fbr: float,
) -> dict[str, Any]:
    """Quality index: Q = 0.35 * F1_intent + 0.25 * (1 - ECE) + 0.20 * nDCG@5 + 0.20 * (1 - FBR)."""
    f1 = max(0.0, min(1.0, float(f1_intent)))
    calib = max(0.0, min(1.0, 1.0 - float(ece)))
    rank = max(0.0, min(1.0, float(ndcg5)))
    fab = max(0.0, min(1.0, 1.0 - float(fbr)))

    q = 0.35 * f1 + 0.25 * calib + 0.20 * rank + 0.20 * fab
    q_clamped = round(max(0.0, min(1.0, q)), 6)
    return {
        "value": q_clamped,
        "f1_intent": round(f1, 6),
        "calibration_factor": round(calib, 6),
        "ndcg5": round(rank, 6),
        "fabrication_factor": round(fab, 6),
        "formula": "Q = 0.35 * F1_intent + 0.25 * (1 - ECE) + 0.20 * nDCG@5 + 0.20 * (1 - FBR)",
    }


def percentile_latencies(
    latencies: Sequence[float],
    percentiles: Sequence[int] = (50, 90, 95, 99),
) -> dict[str, float]:
    """Compute exact percentile latencies (p50, p90, p95, p99)."""
    if not latencies:
        return {f"p{p}": 0.0 for p in percentiles}
    sorted_vals = sorted(float(v) for v in latencies)
    n = len(sorted_vals)
    res: dict[str, float] = {}
    for p in percentiles:
        if n == 1:
            res[f"p{p}"] = round(sorted_vals[0], 4)
            continue
        k = (p / 100.0) * (n - 1)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            val = sorted_vals[int(k)]
        else:
            d0 = sorted_vals[int(f)] * (c - k)
            d1 = sorted_vals[int(c)] * (k - f)
            val = d0 + d1
        res[f"p{p}"] = round(val, 4)
    return res


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
    "wilson_score_interval",
    "wilson_interval_dict",
    "cohens_kappa",
    "build_confusion_matrix",
    "classification_metrics",
    "freshness_policy",
    "parse_timestamp",
    "calculate_freshness_score",
    "freshness_decay",
    "assess_provenance",
    "calculate_source_agreement",
    "compute_finding_confidence",
    "calculate_multifactor_confidence",
    "calculate_brier_score",
    "expected_calibration_error",
    "recall_at_k",
    "mrr",
    "ndcg_at_k",
    "safety_block_rate",
    "false_block_rate",
    "breach_rate",
    "scope_breach_rate",
    "fabrication_rate",
    "grounding_ratio",
    "quality_index",
    "percentile_latencies",
]
