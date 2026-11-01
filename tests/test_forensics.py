import hashlib

import pytest

from redloop.forensics import (
    MAX_FILE_SIZE,
    ForensicsAnalyzer,
    YaraMatch,
)
from redloop.memory import EpisodicMemory


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append(
            {
                "target": target,
                "action": action,
                "module": module,
                "status": status,
                "details": details or {},
            }
        )


class FakeYaraScanner:
    def __init__(self, matches=None):
        self.matches = matches or []
        self.scanned = []

    def scan(self, file_bytes):
        self.scanned.append(file_bytes)
        return self.matches


def test_static_analysis_hashes_metadata_and_extracts_plaintext_iocs():
    audit = FakeAudit()
    sample = (
        b"contact http://updates.example.test/path "
        b"ip 192.0.2.44 email analyst@example.test"
    )
    analyzer = ForensicsAnalyzer(audit)

    report = analyzer.analyze(sample, r"..\samples\demo.txt")

    assert report.profile.filename == "demo.txt"
    assert report.profile.sha256 == hashlib.sha256(sample).hexdigest()
    assert report.profile.md5 == hashlib.md5(sample, usedforsecurity=False).hexdigest()
    assert report.profile.file_type == "text/plain"
    assert report.profile.size_bytes == len(sample)
    assert report.iocs.ips == ["192.0.2.44"]
    assert report.iocs.domains == ["example.test", "updates.example.test"]
    assert report.iocs.urls == ["http://updates.example.test/path"]
    assert report.iocs.emails == ["analyst@example.test"]
    assert report.yara_status == "not_configured"
    assert audit.entries[0]["target"] == report.profile.sha256
    assert "192.0.2.44" not in str(audit.entries[0]["details"])


def test_file_signature_and_entropy_are_reported():
    analyzer = ForensicsAnalyzer(FakeAudit())
    sample = b"\x7fELF" + bytes(range(256)) * 20

    report = analyzer.analyze(sample, "sample.bin")

    assert report.profile.file_type == "application/x-elf"
    assert report.profile.entropy > 7.9
    assert report.profile.warnings


def test_empty_file_has_zero_entropy():
    report = ForensicsAnalyzer(FakeAudit()).analyze(b"", "empty")

    assert report.profile.entropy == 0
    assert report.profile.file_type == "application/octet-stream"


def test_size_limit_is_enforced_and_audited():
    audit = FakeAudit()
    analyzer = ForensicsAnalyzer(audit, max_file_size=4)

    with pytest.raises(ValueError, match="exceeds 4 byte limit"):
        analyzer.analyze(b"12345", "large.bin")

    assert audit.entries[0]["status"] == "blocked"
    assert audit.entries[0]["details"]["reason"] == "file_size_limit"


def test_yara_results_are_returned_but_only_counts_are_audited():
    audit = FakeAudit()
    match = YaraMatch(rule_name="TrainingRule", tags=["training"], meta={"family": "demo"})
    scanner = FakeYaraScanner([match])

    report = ForensicsAnalyzer(audit, yara_scanner=scanner).analyze(
        b"synthetic fixture", "fixture.bin"
    )

    assert scanner.scanned == [b"synthetic fixture"]
    assert report.yara_status == "scanned"
    assert report.yara_matches == [match]
    assert audit.entries[0]["details"]["yara_match_count"] == 1
    assert "TrainingRule" not in str(audit.entries[0]["details"])


def test_invalid_ip_is_not_reported_as_ioc():
    iocs = ForensicsAnalyzer._extract_iocs(
        b"invalid 999.999.999.999 and valid 198.51.100.8"
    )

    assert iocs.ips == ["198.51.100.8"]


def test_non_bytes_input_is_rejected():
    analyzer = ForensicsAnalyzer(FakeAudit())

    with pytest.raises(TypeError, match="must be bytes"):
        analyzer.analyze("not bytes", "sample.txt")


def test_rule_limits_stay_below_file_cap():
    assert MAX_FILE_SIZE == 16 * 1024 * 1024


def test_forensics_outcome_is_added_to_memory_without_sample_iocs(tmp_path):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")
    sample = b"contact 203.0.113.22 at http://sample.example.test/path"

    ForensicsAnalyzer(FakeAudit(), memory=memory).analyze(sample, "sample.txt")

    matches = memory.retrieve_similar("static file triage", module="forensics")
    assert len(matches) == 1
    assert matches[0].record.outcome == "success"
    assert "203.0.113.22" not in matches[0].record.details
    assert "sample.example.test" not in matches[0].record.details
