"""Secret scanner for pre-commit hooks and CI pipelines.

Enforces:
- Zero secrets in production source files (src/, scripts/, configs, root).
- Zero non-synthetic secrets in test suites.
- Fails with exit code 1 if a potential active secret is detected.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "Groq API Key": re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}"),
    "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),
    "Anthropic API Key": re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
    "Google API Key": re.compile(r"AIza[a-zA-Z0-9_\-]{30,}"),
    "Generic Bearer Token": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{25,}", re.IGNORECASE),
}

EXCLUDE_EXTS = {".png", ".jpg", ".jpeg", ".ico", ".svg", ".lock", ".coverage", ".pyc"}
EXCLUDE_DIRS = {"artifacts", ".git", "__pycache__", ".pytest_cache", "dist", "build"}

SYNTHETIC_MARKERS = ("dummy", "mock", "example", "placeholder", "fake", "redacted", "test", "123456", "abcdef", "xyz99")

def is_exempt_file(path_str: str) -> bool:
    p = Path(path_str)
    if p.suffix in EXCLUDE_EXTS:
        return True
    if any(part in EXCLUDE_DIRS for part in p.parts):
        return True
    if p.name.endswith(".example") or "fixture" in path_str.lower():
        return True
    return False

def scan_files(files: list[str]) -> list[dict[str, str]]:
    findings = []
    for f in files:
        if is_exempt_file(f):
            continue
        p = Path(f)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        is_test_file = "test" in f.lower()

        for stype, pat in PATTERNS.items():
            for m in pat.finditer(content):
                val = m.group(0)
                val_lower = val.lower()
                
                # Check surrounding context (current line)
                start_line = content.rfind("\n", 0, m.start()) + 1
                end_line = content.find("\n", m.end())
                if end_line == -1:
                    end_line = len(content)
                line_text = content[start_line:end_line].lower()

                # If in a test file and marked as fake/test/dummy, allow it
                if is_test_file and any(m in val_lower or m in line_text for m in SYNTHETIC_MARKERS):
                    continue

                findings.append({
                    "file": f,
                    "type": stype,
                    "line": content[:m.start()].count("\n") + 1,
                })
    return findings

def main():
    parser = argparse.ArgumentParser(description="Scan repository for hardcoded secrets.")
    parser.add_argument("--staged", action="store_true", help="Scan only git staged files (for pre-commit)")
    parser.add_argument("--all", action="store_true", help="Scan all tracked files in git repository")
    args = parser.parse_args()

    if args.staged:
        cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    else:
        cmd = ["git", "ls-files"]

    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    files = [line.strip() for line in res.stdout.splitlines() if line.strip()]

    findings = scan_files(files)

    if findings:
        print("=" * 60, file=sys.stderr)
        print("SECURITY VIOLATION: Potential secrets detected by scanner!", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        for item in findings:
            print(f"  - [{item['type']}] {item['file']}:{item['line']}", file=sys.stderr)
        print("\nPlease remove the secret, place it in .env (gitignored), or use a placeholder.", file=sys.stderr)
        sys.exit(1)

    print("Secret scan passed: zero unredacted production secrets found.")
    sys.exit(0)

if __name__ == "__main__":
    main()
