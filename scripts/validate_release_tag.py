"""
scripts/validate_release_tag.py

Release tag validation and generation utility for RedLoop.
Enforces Semantic Versioning (SemVer) hygiene, prevents wild version jumps
(e.g., v0.2.0 -> v10.0.0), and calculates the next legitimate release tag.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore

SEMVER_REGEX = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$")


def parse_semver(tag: str) -> Tuple[int, int, int, Optional[int]]:
    """Parse a SemVer string into (major, minor, patch, optional build/run)."""
    m = SEMVER_REGEX.match(tag.strip())
    if not m:
        raise ValueError(f"Invalid semver tag format: '{tag}'")
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3))
    build = int(m.group(4)) if m.group(4) is not None else None
    return major, minor, patch, build


def get_pyproject_version(root_dir: Optional[Path] = None) -> str:
    """Read the base version declared in pyproject.toml."""
    if root_dir is None:
        root_dir = Path(__file__).resolve().parent.parent
    pyproject_path = root_dir / "pyproject.toml"
    if not pyproject_path.exists():
        return "0.2.0"
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    return str(data.get("project", {}).get("version", "0.2.0"))


def get_latest_git_tag() -> str:
    """Retrieve the highest valid release tag from git tags."""
    try:
        proc = subprocess.run(
            ["git", "tag", "-l", "v*"],
            capture_output=True,
            text=True,
            check=True,
        )
        tags = proc.stdout.strip().splitlines()
        valid_tags = []
        for t in tags:
            t = t.strip()
            # Ignore legacy corrupted jumps if encountered
            if not t or t == "v10.0.0":
                continue
            try:
                parsed = parse_semver(t)
                valid_tags.append((parsed, t))
            except ValueError:
                continue

        if not valid_tags:
            return "v0.2.0"

        valid_tags.sort(key=lambda item: (item[0][0], item[0][1], item[0][2], item[0][3] or 0))
        return valid_tags[-1][1]
    except Exception:
        return "v0.2.0"


def calculate_next_tag(current_tag: str, bump_type: str = "patch") -> str:
    """Calculate the next release tag from current_tag."""
    maj, min_, pat, _ = parse_semver(current_tag)
    if bump_type == "minor":
        return f"v{maj}.{min_ + 1}.0"
    elif bump_type == "major":
        return f"v{maj + 1}.0.0"
    else:  # patch
        return f"v{maj}.{min_}.{pat + 1}"


def validate_tag_progression(current_tag: str, proposed_tag: str) -> Tuple[bool, str]:
    """
    Validates that proposed_tag represents a sane and safe transition from current_tag.
    Fails on regression, duplicate, or wild major/minor leaps (e.g., v0.2.0 -> v10.0.0).
    """
    try:
        c_maj, c_min, c_pat, _ = parse_semver(current_tag)
        p_maj, p_min, p_pat, _ = parse_semver(proposed_tag)
    except ValueError as e:
        return False, str(e)

    if (p_maj, p_min, p_pat) <= (c_maj, c_min, c_pat):
        return False, (
            f"Proposed tag {proposed_tag} is not greater than current tag {current_tag} "
            f"({p_maj}.{p_min}.{p_pat} <= {c_maj}.{c_min}.{c_pat})"
        )

    # Prevent major leaps > 1
    if p_maj > c_maj + 1:
        return False, (
            f"Invalid major version jump: {c_maj} -> {p_maj} (maximum permitted jump is +1)"
        )

    # If within same major, prevent minor leaps > 1
    if p_maj == c_maj:
        if p_min > c_min + 1:
            return False, (
                f"Invalid minor version jump: {c_maj}.{c_min} -> {p_maj}.{p_min} (maximum permitted jump is +1)"
            )
        # If within same minor, allow patch increment or build progression
        if p_min == c_min and p_pat > c_pat + 1:
            return False, (
                f"Invalid patch version jump: {c_maj}.{c_min}.{c_pat} -> {p_maj}.{p_min}.{p_pat} "
                f"(maximum permitted jump is +1)"
            )

    return True, "Valid semver progression"


def main() -> int:
    parser = argparse.ArgumentParser(description="Release Tag SemVer Validator")
    parser.add_argument("--candidate", help="Proposed release tag to validate (e.g. v0.2.1)")
    parser.add_argument("--current", help="Current latest release tag (default: auto-detect)")
    parser.add_argument("--compute-next", action="store_true", help="Print next safe patch tag")
    args = parser.parse_args()

    current = args.current or get_latest_git_tag()
    base_ver = get_pyproject_version()

    # Align current with pyproject if computing next and git tag is behind
    if args.compute_next and not args.current:
        try:
            c_parsed = parse_semver(current)
            b_parsed = parse_semver(base_ver)
            if (b_parsed[0], b_parsed[1], b_parsed[2]) > (c_parsed[0], c_parsed[1], c_parsed[2]):
                # If pyproject has been bumped to base_ver, that is the candidate tag
                print(f"v{base_ver}")
                return 0
        except Exception:
            pass

    if args.compute_next:
        next_tag = calculate_next_tag(current, bump_type="patch")
        print(next_tag)
        return 0

    if args.candidate:
        candidate = args.candidate
        valid, msg = validate_tag_progression(current, candidate)
        if not valid:
            print(f"RELEASE HYGIENE ERROR: {msg}", file=sys.stderr)
            return 1
        print(f"RELEASE HYGIENE PASSED: Tag {candidate} is valid progression from {current}")
        return 0

    # Default output: show current and next
    print(f"Current Tag: {current}")
    print(f"Next Patch:  {calculate_next_tag(current, 'patch')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

