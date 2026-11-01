import pytest

from redloop.audit import AuditLogger
from redloop.identity_correlation import (
    CLASSIFICATION_CONFIRMED,
    CLASSIFICATION_CONFLICTING,
    CLASSIFICATION_POSSIBLE,
    CLASSIFICATION_STRONG,
    CLASSIFICATION_UNVERIFIED,
    IdentityCorrelationStore,
    IdentityObservation,
    REVIEW_CONFIRM,
    REVIEW_REJECT,
)


def _store(tmp_path):
    return IdentityCorrelationStore(tmp_path / "identity.sqlite")


def test_same_value_from_two_sources_forms_one_cluster(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation(
            "email",
            "analyst@example.com",
            "github",
            "public_commits",
            confidence=0.7,
            classification=CLASSIFICATION_STRONG,
        )
    )
    store.add_observation(
        IdentityObservation(
            "email",
            "ANALYST@example.com",
            "pgp",
            "keyserver",
            confidence=0.7,
            classification=CLASSIFICATION_STRONG,
        )
    )
    clusters = store.build_clusters()
    assert len(clusters) == 1
    assert clusters[0].classification == CLASSIFICATION_CONFIRMED
    assert clusters[0].confidence >= 0.8
    assert len(clusters[0].observations) == 2


def test_usernames_from_two_sources_never_auto_confirm(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation(
            "username",
            "analyst",
            "github",
            "profile_lookup",
            confidence=0.9,
            classification=CLASSIFICATION_CONFIRMED,
        )
    )
    store.add_observation(
        IdentityObservation(
            "username",
            "analyst",
            "mastodon",
            "profile_lookup",
            confidence=0.9,
            classification=CLASSIFICATION_CONFIRMED,
        )
    )
    cluster = store.build_clusters()[0]
    assert cluster.classification != CLASSIFICATION_CONFIRMED
    assert cluster.classification == CLASSIFICATION_STRONG
    assert cluster.confidence < 0.95


def test_profile_images_from_two_sources_never_auto_confirm(tmp_path):
    store = _store(tmp_path)
    for source in ("source_a", "source_b"):
        store.add_observation(
            IdentityObservation(
                "public_profile",
                "https://example.com/profile",
                source,
                "avatar_similarity",
                confidence=0.9,
                classification=CLASSIFICATION_STRONG,
            )
        )
    cluster = store.build_clusters()[0]
    assert cluster.classification != CLASSIFICATION_CONFIRMED
    assert cluster.classification == CLASSIFICATION_STRONG


def test_confirming_identifier_plus_username_can_confirm(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation(
            "email",
            "analyst@example.com",
            "pgp",
            "keyserver",
            confidence=0.75,
            classification=CLASSIFICATION_STRONG,
            correlation_key="case-99",
        )
    )
    store.add_observation(
        IdentityObservation(
            "username",
            "analyst",
            "github",
            "public_profile",
            confidence=0.7,
            classification=CLASSIFICATION_STRONG,
            correlation_key="case-99",
        )
    )
    cluster = store.build_clusters()[0]
    assert cluster.classification == CLASSIFICATION_CONFIRMED
    assert cluster.confidence >= 0.8


def test_single_observation_is_unverified(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation("username", "@analyst", "manual", "paste", confidence=0.9)
    )
    cluster = store.build_clusters()[0]
    assert cluster.classification == CLASSIFICATION_UNVERIFIED
    assert cluster.confidence is None


def test_explicit_correlation_key_links_different_entities(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation(
            "email",
            "analyst@example.com",
            "github",
            "public_commits",
            confidence=0.7,
            classification=CLASSIFICATION_STRONG,
            correlation_key="case-42",
        )
    )
    store.add_observation(
        IdentityObservation(
            "username",
            "analyst",
            "manual",
            "analyst_assertion",
            confidence=0.5,
            classification=CLASSIFICATION_POSSIBLE,
            correlation_key="case-42",
        )
    )
    clusters = store.build_clusters()
    assert len(clusters) == 1
    assert {o.entity_type for o in clusters[0].observations} == {"email", "username"}
    assert clusters[0].classification == CLASSIFICATION_STRONG


def test_conflicting_evidence_is_never_averaged_into_confidence(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation(
            "email",
            "analyst@example.com",
            "source_a",
            "record",
            classification=CLASSIFICATION_CONFLICTING,
        )
    )
    store.add_observation(
        IdentityObservation(
            "email",
            "analyst@example.com",
            "source_b",
            "record",
            classification=CLASSIFICATION_STRONG,
            confidence=0.7,
        )
    )
    cluster = store.build_clusters()[0]
    assert cluster.classification == CLASSIFICATION_CONFLICTING
    assert cluster.confidence is None


def test_analyst_confirm_persists_and_overrides(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation("email", "analyst@example.com", "manual", "operator")
    )
    cluster = store.build_clusters()[0]
    assert cluster.classification == CLASSIFICATION_UNVERIFIED

    reviewed = store.review(cluster.cluster_id, REVIEW_CONFIRM, "alice", "matched passport")
    assert reviewed["review_status"] == "CONFIRMED"
    assert reviewed["classification"] == CLASSIFICATION_CONFIRMED
    assert reviewed["confidence"] >= 0.95
    assert reviewed["reviews"][0]["analyst"] == "alice"
    assert reviewed["review_note"] == "matched passport"
    assert reviewed["reviewed_at"]
    assert reviewed["reviews"][0]["created_at"]
    assert reviewed["reviews"][0]["decision"] == REVIEW_CONFIRM

    rebuilt = store.build_clusters()[0]
    assert rebuilt.review_status == "CONFIRMED"
    assert rebuilt.classification == CLASSIFICATION_CONFIRMED


def test_analyst_reject_downgrades_without_deleting_evidence(tmp_path):
    store = _store(tmp_path)
    store.add_observation(
        IdentityObservation(
            "email",
            "analyst@example.com",
            "github",
            "commits",
            classification=CLASSIFICATION_STRONG,
            confidence=0.7,
        )
    )
    cluster = store.build_clusters()[0]
    reviewed = store.review(cluster.cluster_id, REVIEW_REJECT, "bob", "wrong person")
    assert reviewed["review_status"] == "REJECTED"
    assert reviewed["classification"] == CLASSIFICATION_UNVERIFIED
    assert reviewed["confidence"] is None
    assert reviewed["member_count"] == 1
    assert len(store.list_reviews(cluster.cluster_id)) == 1


def test_review_requires_analyst_and_valid_decision(tmp_path):
    store = _store(tmp_path)
    store.add_observation(IdentityObservation("email", "a@b.co", "manual", "operator"))
    cluster = store.build_clusters()[0]
    with pytest.raises(ValueError):
        store.review(cluster.cluster_id, "CONFIRM", "")
    with pytest.raises(ValueError):
        store.review(cluster.cluster_id, "MAYBE", "alice")
    with pytest.raises(KeyError):
        store.review("missing", REVIEW_CONFIRM, "alice")


def test_review_writes_audit_trail(tmp_path):
    store = _store(tmp_path)
    audit = AuditLogger(tmp_path / "audit.sqlite")
    store.add_observation(IdentityObservation("email", "a@b.co", "manual", "operator"))
    cluster = store.build_clusters()[0]
    store.review(cluster.cluster_id, REVIEW_CONFIRM, "alice", audit=audit)
    rows = audit.fetch(module="identity")
    assert len(rows) == 1
    assert rows[0]["action"] == "identity_cluster_review"


def test_invalid_observation_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        IdentityObservation("ssn", "123-45-6789", "manual", "operator")
    with pytest.raises(ValueError):
        IdentityObservation("email", "   ", "manual", "operator")


def test_evidence_hash_detects_observation_tampering(tmp_path):
    obs = IdentityObservation("email", "a@b.co", "manual", "operator")
    assert obs.verify_evidence()
    obs.value = "attacker@example.com"
    assert obs.verify_evidence() is False
