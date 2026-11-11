"""
tests/test_release_hygiene.py

Regression test suite for release hygiene, SemVer enforcement, and tag validation.
Guarantees that wild version jumps (e.g. v10.0.0) are strictly rejected and that
the release pipeline cannot generate or accept non-monotonic or disproportionate tags.
"""

import subprocess
import pytest
from scripts.validate_release_tag import (
    parse_semver,
    calculate_next_tag,
    validate_tag_progression,
    get_latest_git_tag,
)


class TestSemVerParsing:
    def test_parse_standard_semver(self):
        assert parse_semver("v0.2.0") == (0, 2, 0, None)
        assert parse_semver("v1.5.12") == (1, 5, 12, None)
        assert parse_semver("0.3.4") == (0, 3, 4, None)

    def test_parse_four_part_run_number(self):
        assert parse_semver("v0.1.0.4") == (0, 1, 0, 4)

    def test_reject_invalid_semver_strings(self):
        with pytest.raises(ValueError):
            parse_semver("release-final")
        with pytest.raises(ValueError):
            parse_semver("v1.0")
        with pytest.raises(ValueError):
            parse_semver("abc.def.ghi")


class TestTagProgressionGuards:
    def test_reject_wild_major_jump_v10(self):
        """Regression test for the stray v10.0.0 tag bug."""
        valid, msg = validate_tag_progression("v0.2.0", "v10.0.0")
        assert not valid
        assert "Invalid major version jump: 0 -> 10" in msg

    def test_reject_multiple_major_jump(self):
        valid, msg = validate_tag_progression("v0.2.0", "v2.0.0")
        assert not valid
        assert "Invalid major version jump" in msg

    def test_reject_multiple_minor_jump(self):
        valid, msg = validate_tag_progression("v0.2.0", "v0.4.0")
        assert not valid
        assert "Invalid minor version jump" in msg

    def test_reject_multiple_patch_jump(self):
        valid, msg = validate_tag_progression("v0.2.0", "v0.2.4")
        assert not valid
        assert "Invalid patch version jump" in msg

    def test_reject_regression_or_duplicate(self):
        valid, msg = validate_tag_progression("v0.2.0", "v0.2.0")
        assert not valid
        assert "not greater than" in msg

        valid_reg, msg_reg = validate_tag_progression("v0.2.0", "v0.1.9")
        assert not valid_reg
        assert "not greater than" in msg_reg

    def test_accept_valid_patch_progression(self):
        valid, msg = validate_tag_progression("v0.2.0", "v0.2.1")
        assert valid
        assert "Valid semver progression" in msg

    def test_accept_valid_minor_progression(self):
        valid, msg = validate_tag_progression("v0.2.0", "v0.3.0")
        assert valid
        assert "Valid semver progression" in msg

    def test_calculate_next_patch_tag(self):
        assert calculate_next_tag("v0.2.0", "patch") == "v0.2.1"
        assert calculate_next_tag("v1.4.9", "patch") == "v1.4.10"

    def test_stray_v10_absent_from_git_tags(self):
        """Verifies that the stray v10.0.0 tag has been completely expunged from git."""
        proc = subprocess.run(
            ["git", "tag", "-l"],
            capture_output=True,
            text=True,
            check=True,
        )
        tags = [t.strip() for t in proc.stdout.splitlines() if t.strip()]
        assert "v10.0.0" not in tags, f"v10.0.0 is still present in git tags: {tags}"

    def test_latest_real_tag_is_sane(self):
        latest = get_latest_git_tag()
        assert latest == "v0.2.0"
        next_tag = calculate_next_tag(latest, "patch")
        assert next_tag == "v0.2.1"

