import base64
import io
import json
import zipfile

import pytest
from typer.testing import CliRunner

from redloop.audit import AuditLogger
from redloop.ctf_files import CTFArchiveAnalyzer, FileCategory, find_flags
from redloop.memory import EpisodicMemory


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def test_find_flags_detects_standard_generic_and_custom_prefixes():
    found = find_flags(
        "flag{plain} CTF{standard} custom_format{value-1} site-flag{custom}",
        custom_prefixes=["site-flag"],
    )

    assert found == [
        "CTF{standard}",
        "custom_format{value-1}",
        "flag{plain}",
        "site-flag{custom}",
    ]


def test_analyzer_finds_plain_and_base64_encoded_flags():
    encoded_flag = base64.b64encode(b"CTF{decoded_from_base64}").decode("ascii")
    archive_bytes = make_zip(
        {
            "notes.txt": b"flag{plain_text}",
            "payload.txt": f"encoded={encoded_flag}".encode("ascii"),
        }
    )

    report = CTFArchiveAnalyzer().analyze(archive_bytes, "challenge.zip")

    assert report.status == "solved"
    assert report.examined_files == 2
    assert report.flags == ["CTF{decoded_from_base64}", "flag{plain_text}"]
    assert all(item.category == FileCategory.TEXT for item in report.files)
    payload = next(item for item in report.files if item.path == "payload.txt")
    assert "base64" in payload.decode_methods


def test_analyzer_recurses_through_nested_zip_without_extracting(tmp_path):
    inner = make_zip({"nested.txt": b"picoCTF{inside_nested_archive}"})
    outer = make_zip({"nested.zip": inner, "../outside.txt": b"no extraction"})

    report = CTFArchiveAnalyzer().analyze(outer, "outer.zip")

    assert report.flags == ["picoCTF{inside_nested_archive}"]
    assert any(item.path == "nested.zip/nested.txt" for item in report.files)
    assert not (tmp_path.parent / "outside.txt").exists()


def test_analyzer_supports_hex_and_rot13_decoding():
    hex_flag = b"flag{hex_layer}".hex().encode("ascii")
    rot13_flag = b"CTF{rot13_layer}".decode("ascii").translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )
    archive_bytes = make_zip(
        {"hex.txt": hex_flag, "rot13.txt": rot13_flag.encode("ascii")}
    )

    report = CTFArchiveAnalyzer().analyze(archive_bytes, "encoded.zip")

    assert report.flags == ["CTF{rot13_layer}", "flag{hex_layer}"]
    assert "hex" in next(item for item in report.files if item.path == "hex.txt").decode_methods
    assert "rot13" in next(item for item in report.files if item.path == "rot13.txt").decode_methods


def test_analyzer_rejects_non_zip_input():
    with pytest.raises(ValueError, match="valid ZIP"):
        CTFArchiveAnalyzer().analyze(b"not a zip", "sample.zip")


def test_analyzer_skips_entries_over_the_per_file_limit():
    archive_bytes = make_zip(
        {
            "oversized.txt": b"A" * (4 * 1024 * 1024 + 1),
            "normal.txt": b"flag{still_scanned}",
        }
    )

    report = CTFArchiveAnalyzer().analyze(archive_bytes, "bounded.zip")

    oversized = next(item for item in report.files if item.path == "oversized.txt")
    assert oversized.skipped_reason == "entry_size_limit"
    assert report.flags == ["flag{still_scanned}"]
    assert report.warnings


def test_analysis_outcomes_do_not_persist_flags_or_archive_paths(tmp_path):
    audit = AuditLogger(tmp_path / "audit.sqlite")
    memory = EpisodicMemory(tmp_path / "memory.sqlite", audit=audit)
    archive_bytes = make_zip({"secret.txt": b"flag{do_not_persist_this_value}"})

    report = CTFArchiveAnalyzer(audit=audit, memory=memory).analyze(
        archive_bytes, "private-challenge.zip"
    )

    assert report.flags == ["flag{do_not_persist_this_value}"]
    audit_rows = audit.fetch(module="ctf_file_analyzer")
    assert len(audit_rows) == 1
    assert audit_rows[0]["target"].startswith("archive-sha256:")
    assert audit_rows[0]["status"] == "success"
    assert "do_not_persist_this_value" not in json.dumps(audit_rows)
    assert "private-challenge.zip" not in json.dumps(audit_rows)
    matches = memory.retrieve_similar(
        "local CTF archive flag analysis", module="ctf_file_analyzer"
    )
    assert len(matches) == 1
    assert matches[0].record.outcome == "success"
    assert "do_not_persist_this_value" not in matches[0].record.details


def test_cli_solves_local_archive_without_execution(tmp_path, monkeypatch):
    from redloop import cli

    archive_path = tmp_path / "fixture.zip"
    archive_path.write_bytes(make_zip({"readme.txt": b"flag{cli_fixture}"}))
    monkeypatch.setattr(cli, "_get_audit", lambda: None)
    monkeypatch.setattr(cli, "_get_memory", lambda: None)

    result = CliRunner().invoke(
        cli.app, ["ctf", "solve-file", str(archive_path)]
    )

    assert result.exit_code == 0, result.output
    assert '"status": "solved"' in result.output
    assert "flag{cli_fixture}" in result.output
