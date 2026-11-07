from datetime import datetime, timedelta, timezone

from redloop.assessment.metrics import (
    CONFIDENCE_WEIGHTS,
    HEURISTIC_CONFIDENCE,
    INSUFFICIENT_EVIDENCE,
    METRIC_NOT_APPLICABLE,
    NOT_CALIBRATED,
    SINGLE_SOURCE,
    assess_provenance,
    calculate_brier_score,
    calculate_f1_nullable,
    calculate_freshness_score,
    calculate_precision_nullable,
    calculate_recall_nullable,
    calculate_source_agreement,
    classification_metrics,
    compute_finding_confidence,
    expected_calibration_error,
    freshness_decay,
)


def test_null_safe_classification_metrics_report_not_applicable():
    assert calculate_precision_nullable(0, 0) is None
    assert calculate_recall_nullable(0, 0) is None
    assert calculate_f1_nullable(None, 0.5) is None
    assert calculate_f1_nullable(0.0, 0.0) is None

    result = classification_metrics([], [])
    assert result["status"] == METRIC_NOT_APPLICABLE
    assert result["accuracy"] is None
    assert result["macro_f1"] is None


def test_classification_metrics_match_known_confusion_matrix():
    y_true = ["port", "port", "cve", "dns"]
    y_pred = ["port", "cve", "cve", "dns"]
    result = classification_metrics(y_true, y_pred)
    assert result["status"] == "COMPUTED"
    assert result["accuracy"] == 0.75
    assert result["per_class"]["cve"]["precision"] == 0.5
    assert result["per_class"]["cve"]["recall"] == 1.0
    assert result["per_class"]["dns"]["precision"] == 1.0
    assert result["per_class"]["dns"]["recall"] == 1.0
    assert result["macro_f1"] is not None
    assert result["confusion_matrix"]["sample_count"] == 4


def test_five_factor_confidence_does_not_award_single_source_agreement():
    result = compute_finding_confidence(
        source_reliability=1.0,
        independent_source_count=1,
        evidence_integrity=1.0,
        freshness=1.0,
        provenance_completeness=1.0,
    )
    assert result["label"] == HEURISTIC_CONFIDENCE
    assert result["status"] == SINGLE_SOURCE
    assert result["factors"]["source_agreement"] == 0.0
    assert result["score"] is not None
    assert result["score"] < 1.0
    assert result["calibration_status"] == NOT_CALIBRATED


def test_five_factor_confidence_weights_and_score():
    assert CONFIDENCE_WEIGHTS == {
        "source_reliability": 0.30,
        "source_agreement": 0.20,
        "evidence_integrity": 0.20,
        "freshness": 0.15,
        "provenance_completeness": 0.15,
    }
    result = compute_finding_confidence(
        source_reliability=1.0,
        source_agreement=1.0,
        independent_source_count=2,
        evidence_integrity=1.0,
        freshness=1.0,
        provenance_completeness=1.0,
    )
    assert result["score"] == 1.0
    assert result["label"] == HEURISTIC_CONFIDENCE
    assert result["status"] == HEURISTIC_CONFIDENCE
    assert result["calibration_status"] == NOT_CALIBRATED


def test_five_factor_confidence_refuses_without_source_reliability():
    result = compute_finding_confidence(
        source_reliability=None,
        source_agreement=1.0,
        evidence_integrity=1.0,
    )
    assert result["status"] == INSUFFICIENT_EVIDENCE
    assert result["score"] is None
    assert result["label"] == HEURISTIC_CONFIDENCE


def test_source_agreement_single_source_is_explicit():
    single = calculate_source_agreement(["RDAP/ARIN"])
    assert single["status"] == SINGLE_SOURCE
    assert single["score"] is None

    corroborated = calculate_source_agreement(
        ["RDAP/ARIN", "DNS_PTR_QUERY", "rdap/arin"],
        ["8.8.8.8", "8.8.8.8", "8.8.4.4"],
    )
    assert corroborated["status"] == "CORROBORATED"
    assert corroborated["independent_sources"] == 2
    assert corroborated["score"] == 0.6667


def test_freshness_uses_exponential_half_life_decay():
    now = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
    assert calculate_freshness_score(now, 3600, now) == 1.0
    one_half_life = calculate_freshness_score(now - timedelta(hours=1), 3600, now)
    assert round(one_half_life, 6) == 0.5
    two_half_lives = calculate_freshness_score(now - timedelta(hours=2), 3600, now)
    assert round(two_half_lives, 6) == 0.25
    assert calculate_freshness_score("not-a-timestamp", 3600, now) is None

    decay = freshness_decay(
        (now - timedelta(hours=1)).isoformat(),
        observation_type="dns",
        now=now,
    )
    assert decay["status"] == "DECAYED"
    assert decay["score"] == 0.5
    assert decay["decay_fraction"] == 0.5
    assert decay["half_life_seconds"] == 3600.0
    assert decay["age_seconds"] == 3600.0

    fresh = freshness_decay(now.isoformat(), observation_type="dns", now=now)
    assert fresh["status"] == "FRESH"
    assert fresh["score"] == 1.0
    assert fresh["decay_fraction"] == 0.0


def test_provenance_reports_missing_fields_instead_of_guessing():
    complete = assess_provenance(
        {
            "source": "rdap",
            "timestamp": "2026-10-31T12:00:00Z",
            "method": "https_get",
            "evidence_id": "evi-1",
            "confidence": 0.9,
        }
    )
    assert complete["score"] == 1.0
    assert complete["status"] == "COMPLETE"

    partial = assess_provenance(
        {"source": "rdap", "confidence": 2.0},
        required_fields=("source", "timestamp", "method", "evidence", "confidence"),
    )
    assert partial["status"] == "INCOMPLETE"
    assert partial["score"] == 0.2
    assert "confidence" in partial["missing_fields"]
    assert "timestamp" in partial["missing_fields"]


def test_calibration_refuses_small_samples_and_computes_brier():
    assert calculate_brier_score([], []) is None
    assert calculate_brier_score([0.9, 0.1], [1, 0]) == 0.01
    assert calculate_brier_score([1.5], [1]) is None

    refused = expected_calibration_error([0.9] * 5, [1] * 5)
    assert refused["status"] == NOT_CALIBRATED
    assert refused["score"] is None

    computed = expected_calibration_error(
        [0.9, 0.8, 0.7, 0.6, 0.4, 0.3, 0.2, 0.1, 0.95, 0.85],
        [1, 1, 0, 1, 0, 0, 0, 0, 1, 1],
    )
    assert computed["status"] == "COMPUTED"
    assert computed["calibration_claim"] == NOT_CALIBRATED
    assert computed["score"] is not None
    assert computed["brier_score"] is not None
    assert computed["sample_count"] == 10


def test_wilson_score_interval():
    from redloop.assessment.metrics import wilson_score_interval, wilson_interval_dict

    # Edge cases
    assert wilson_score_interval(0, 0) == (0.0, 0.0)
    lower, upper = wilson_score_interval(50, 100)
    assert 0.39 < lower < 0.41
    assert 0.59 < upper < 0.61

    # 100% success
    low_100, up_100 = wilson_score_interval(10, 10)
    assert low_100 > 0.65
    assert up_100 == 1.0

    d = wilson_interval_dict(95, 100)
    assert d["value"] == 0.95
    assert d["sample_size"] == 100
    assert "ci95_lower" in d
    assert "ci95_upper" in d


def test_cohens_kappa_calculation():
    from redloop.assessment.metrics import cohens_kappa

    # Perfect agreement
    y1 = ["A", "B", "A", "C"]
    assert cohens_kappa(y1, y1) == 1.0

    # Partial agreement
    y2 = ["A", "B", "C", "C"]
    k = cohens_kappa(y1, y2)
    assert k is not None
    assert 0.0 < k < 1.0

    # Empty
    assert cohens_kappa([], []) is None


def test_ranking_metrics_rag():
    from redloop.assessment.metrics import recall_at_k, mrr, ndcg_at_k

    rel = ["doc1", "doc3"]
    ret = ["doc2", "doc1", "doc4", "doc3", "doc5"]

    # Recall@k
    assert recall_at_k(rel, ret, k=1) == 0.0
    assert recall_at_k(rel, ret, k=2) == 0.5
    assert recall_at_k(rel, ret, k=4) == 1.0

    # MRR (doc1 is at rank 2 => 1/2 = 0.5)
    assert mrr(rel, ret) == 0.5
    assert mrr(["docX"], ret) == 0.0

    # nDCG@k
    score = ndcg_at_k(rel, ret, k=5)
    assert 0.0 < score <= 1.0

    # Perfect ranking
    assert ndcg_at_k(["doc1", "doc2"], ["doc1", "doc2", "doc3"], k=2) == 1.0


def test_multifactor_confidence_formula():
    from redloop.assessment.metrics import calculate_multifactor_confidence

    # Formula: C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X
    perfect = calculate_multifactor_confidence(s=4, d=1.0, i=1.0, f=1.0, p=1.0, x=1.0)
    assert perfect["score"] == 1.0
    assert perfect["factors"]["S"] == 1.0

    partial = calculate_multifactor_confidence(s=2, d=0.5, i=1.0, f=0.5, p=1.0, x=0.5)
    # S=2/4=0.5 (0.25*0.5 = 0.125)
    # D=0.5 (0.25*0.5 = 0.125)
    # I=1.0 (0.20*1.0 = 0.20)
    # F=0.5 (0.10*0.5 = 0.05)
    # P=1.0 (0.10*1.0 = 0.10)
    # X=0.5 (0.10*0.5 = 0.05)
    # Total = 0.125 + 0.125 + 0.20 + 0.05 + 0.10 + 0.05 = 0.65
    assert partial["score"] == 0.65


def test_operational_metrics():
    from redloop.assessment.metrics import (
        scope_breach_rate,
        fabrication_rate,
        grounding_ratio,
        quality_index,
        percentile_latencies,
    )

    sbr = scope_breach_rate(0, 100)
    assert sbr["value"] == 0.0
    assert sbr["breach_status"] == "PASSED"

    fbr = fabrication_rate(0, 50)
    assert fbr["value"] == 0.0
    assert fbr["fabrication_status"] == "PASSED"

    gr = grounding_ratio(45, 50)
    assert gr["value"] == 0.9

    q = quality_index(f1_intent=0.95, ece=0.05, ndcg5=0.90, fbr=0.0)
    assert 0.9 < q["value"] <= 1.0

    lat = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    p = percentile_latencies(lat)
    assert p["p50"] == 55.0
    assert p["p90"] == 91.0
    assert p["p99"] == 99.1
