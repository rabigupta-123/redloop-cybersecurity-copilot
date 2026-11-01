from contextlib import nullcontext

from redloop.email_footprint import (
    CLASSIFICATION_CONFIRMED,
    CLASSIFICATION_CONFLICTING,
    CLASSIFICATION_NOT_PUBLIC,
    CLASSIFICATION_POSSIBLE,
    CLASSIFICATION_STRONG,
    CLASSIFICATION_UNVERIFIED,
    EmailFootprintEngine,
    FootprintObservation,
    OBS_ERROR,
    OBS_MATCH,
    OBS_NOT_CONFIGURED,
    redact_breach_metadata,
)


class FakeAdapter:
    def __init__(self, name, classification, *, status=OBS_MATCH, confidence=0.7, authoritative=False):
        self.name = name
        self.source = name
        self.reliability = confidence
        self.external = True
        self.env_flag = f"{name.upper()}_ENABLED"
        self.classification = classification
        self.status = status
        self.confidence = confidence
        self.authoritative = authoritative

    def enabled(self):
        return True

    def collect(self, email, domain, http):
        return [
            FootprintObservation(
                self.name,
                self.source,
                self.status,
                classification=self.classification,
                confidence=self.confidence,
                authoritative=self.authoritative,
                title=f"{self.name} result",
            )
        ]


def _engine(*adapters):
    return EmailFootprintEngine(
        adapters=list(adapters),
        network_enabled=True,
        http_factory=lambda: nullcontext(object()),
    )


def test_invalid_email_never_runs_adapters():
    adapter = FakeAdapter("fake", CLASSIFICATION_POSSIBLE)
    report = _engine(adapter).investigate("not-an-email")
    assert report.valid is False
    assert report.observations == []
    assert report.confidence is None
    assert report.classification == CLASSIFICATION_NOT_PUBLIC
    assert "RFC 5322" in report.limitations[0]


def test_single_strong_source_is_not_confirmed():
    report = _engine(FakeAdapter("pgp", CLASSIFICATION_STRONG)).investigate("analyst@example.com")
    assert report.classification == CLASSIFICATION_STRONG
    assert report.confidence is not None
    assert report.confidence < 0.9
    assert report.verify_evidence()


def test_two_independent_strong_sources_confirm_public_association():
    report = _engine(
        FakeAdapter("github", CLASSIFICATION_STRONG),
        FakeAdapter("pgp", CLASSIFICATION_STRONG),
    ).investigate("analyst@example.com")
    assert report.classification == CLASSIFICATION_CONFIRMED
    assert report.confidence is not None
    assert report.confidence >= 0.85
    assert report.confidence_evidence["independent_sources"] == 2


def test_authoritative_single_source_confirms():
    report = _engine(
        FakeAdapter("registry", CLASSIFICATION_CONFIRMED, authoritative=True)
    ).investigate("analyst@example.com")
    assert report.classification == CLASSIFICATION_CONFIRMED


def test_possible_and_unverified_are_kept_low():
    possible = _engine(FakeAdapter("gravatar", CLASSIFICATION_POSSIBLE, confidence=0.35)).investigate(
        "analyst@example.com"
    )
    assert possible.classification == CLASSIFICATION_POSSIBLE
    assert possible.confidence < 0.6

    unverified = _engine(FakeAdapter("mx", CLASSIFICATION_UNVERIFIED, confidence=0.2)).investigate(
        "analyst@example.com"
    )
    assert unverified.classification == CLASSIFICATION_UNVERIFIED


def test_conflicting_evidence_has_no_score():
    report = _engine(
        FakeAdapter("a", CLASSIFICATION_CONFLICTING),
        FakeAdapter("b", CLASSIFICATION_STRONG),
    ).investigate("analyst@example.com")
    assert report.classification == CLASSIFICATION_CONFLICTING
    assert report.confidence is None
    assert report.confidence_evidence["status"] == "INSUFFICIENT_EVIDENCE"


def test_no_public_match_is_not_reported_as_success():
    report = _engine(FakeAdapter("github", CLASSIFICATION_NOT_PUBLIC, status=OBS_ERROR)).investigate(
        "analyst@example.com"
    )
    assert report.classification == CLASSIFICATION_NOT_PUBLIC
    assert report.confidence is None


def test_disabled_network_does_not_fabricate_external_results():
    report = EmailFootprintEngine(
        adapters=[],
        network_enabled=False,
        http_factory=lambda: nullcontext(object()),
    ).investigate("analyst@example.com")
    assert report.network_enabled is False
    assert report.classification == CLASSIFICATION_NOT_PUBLIC
    assert report.confidence is None
    assert report.observations[0].status == "NOT_CHECKED"


def test_breach_metadata_redacts_account_details():
    summary = redact_breach_metadata(
        [
            {
                "Name": "ExampleBreach",
                "BreachDate": "2024-01-01",
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "user@example.com password=hunter2",
            }
        ],
        "user@example.com",
    )
    assert summary["breach_count"] == 1
    assert summary["raw_records_included"] is False
    assert "user@example.com" not in str(summary)
    assert "hunter2" not in str(summary)


def test_evidence_hash_detects_report_tampering():
    report = _engine(FakeAdapter("pgp", CLASSIFICATION_STRONG)).investigate("analyst@example.com")
    assert report.verify_evidence() is True
    report.classification = CLASSIFICATION_CONFIRMED
    assert report.verify_evidence() is False


def test_observation_evidence_hash_detects_tampering():
    observation = FootprintObservation("src", "source", OBS_MATCH)
    assert observation.verify_evidence() is True
    observation.status = "NO_MATCH"
    assert observation.verify_evidence() is False


def test_observation_records_method_timestamp_and_evidence():
    observation = FootprintObservation("pgp", "keys.openpgp.org", OBS_MATCH)
    payload = observation.to_dict()

    assert payload["method"] == "pgp_lookup"
    assert payload["observed_at"]
    assert payload["source"] == "keys.openpgp.org"
    assert payload["url"] is None
    assert payload["evidence_valid"] is True


def test_breach_count_is_unique_not_duplicate_rows():
    summary = redact_breach_metadata(
        [
            {"Name": "ExampleBreach"},
            {"Name": "ExampleBreach"},
            {"Name": "OtherBreach"},
        ],
        "user@example.com",
    )
    assert summary["breach_count"] == 2
    assert summary["breach_names"] == ["ExampleBreach", "OtherBreach"]


def test_network_adapter_failure_is_not_a_match():
    class BrokenAdapter:
        name = "broken"
        source = "broken"
        reliability = 0.5
        external = True
        env_flag = "BROKEN_ENABLED"

        def enabled(self):
            return True

        def collect(self, email, domain, http):
            raise RuntimeError("boom")

    report = _engine(BrokenAdapter()).investigate("analyst@example.com")
    assert report.classification == CLASSIFICATION_NOT_PUBLIC
    assert report.confidence is None
    assert report.observations[0].status == OBS_ERROR
