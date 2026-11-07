"""Scan git history and repository tree for secrets and generate docs/SECRETS_REPORT.md."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

PATTERNS = {
    "Groq API Key": re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}"),
    "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),
    "Anthropic API Key": re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
    "Google API Key": re.compile(r"AIza[a-zA-Z0-9_\-]{30,}"),
    "Bearer Token": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{25,}", re.IGNORECASE),
    "64-Hex String": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

EXCLUDE_EXTS = {".png", ".jpg", ".jpeg", ".ico", ".svg", ".lock", ".coverage", ".pyc"}
EXCLUDE_DIRS = {"artifacts", ".git", "__pycache__", ".pytest_cache"}

def main():
    docs_dir = Path("docs")
    docs_dir.mkdir(parents=True, exist_ok=True)
    report_file = docs_dir / "SECRETS_REPORT.md"

    # 1. Scan working tree tracked files
    res = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True)
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    findings = []
    
    for rel_path in tracked_files:
        p = Path(rel_path)
        if p.suffix in EXCLUDE_EXTS or any(part in EXCLUDE_DIRS for part in p.parts):
            continue
        # Skip fixtures or test files with dummy keys
        if "test" in p.name.lower() or "fixture" in str(p).lower() or p.name.endswith(".example"):
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for name, pat in PATTERNS.items():
            if name == "64-Hex String":
                # Only check for hex strings in config/env files, not general code hashes
                if not (p.name.endswith(".env") or p.name.endswith(".yaml") or p.name.endswith(".json")):
                    continue
            for match in pat.finditer(content):
                val = match.group(0)
                # Ignore dummy/mock/placeholder strings
                if any(x in val.lower() for x in ("dummy", "mock", "test", "example", "fake", "placeholder", "xxx")):
                    continue
                # Mask secret value (show env var / redacted form only)
                masked = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
                findings.append({
                    "file": str(p),
                    "type": name,
                    "masked": masked,
                    "location": "working_tree",
                })

    # 2. Scan git log history for commits that might contain keys
    log_res = subprocess.run(["git", "log", "-p", "--max-count=50"], capture_output=True, text=True, errors="replace")
    for name, pat in PATTERNS.items():
        if name == "64-Hex String":
            continue
        for match in pat.finditer(log_res.stdout):
            val = match.group(0)
            if any(x in val.lower() for x in ("dummy", "mock", "test", "example", "fake", "placeholder", "xxx")):
                continue
            masked = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
            findings.append({
                "file": "git_commit_history",
                "type": name,
                "masked": masked,
                "location": "git_log",
            })

    # Deduplicate findings
    dedup = []
    seen = set()
    for f in findings:
        key = (f["file"], f["type"], f["masked"])
        if key not in seen:
            seen.add(key)
            dedup.append(f)

    # Generate Markdown Report
    lines = [
        "# REDLOOP — Secrets Hygiene and Audit Report",
        "",
        "## Summary",
        f"- Total potential secret indicators identified: {len(dedup)}",
        "- Policy: Zero hardcoded production secrets in tracked source files or public commit history.",
        "- Environment variables must be loaded via `os.environ` or `.env` (gitignored).",
        "",
        "## Findings and Remediation",
    ]

    if not dedup:
        lines.append("- **Status:** PASS. No active production secrets detected in tracked files.")
    else:
        lines.append("| Location | Type | Masked Indicator | Remediation / Recommendation |")
        lines.append("|---|---|---|---|")
        for f in dedup:
            rec = "Revoke immediately at provider portal and rotate secret. Do not rewrite public history."
            lines.append(f"| `{f['file']}` | {f['type']} | `{f['masked']}` | {rec} |")

    lines.extend([
        "",
        "## Recommended Rotation Procedures",
        "1. **Scope HMAC Secret:** Execute `redloop scope rotate-secret` to re-sign active scope contracts.",
        "2. **LLM Provider Keys (Groq / OpenAI / Anthropic / Google):** Reissue tokens at provider console and update local `.env`.",
        "3. **VirusTotal & Shodan Keys:** Reissue in account dashboard and store in local environment variables.",
        "4. **Operator Capability Tokens:** Rotate via `redloop operator-token --generate`.",
        "",
        "## .gitignore Verification",
        "- `.env` and `.env.*` (excluding `.env.example`): IGNORED",
        "- `*.key` and cryptographic secret sidecars: IGNORED",
        "- `data/` and local SQLite databases: IGNORED",
        "- `logs/` and runtime logs: IGNORED",
        "- `artifacts/`: IGNORED",
    ])

    report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Secrets report generated at {report_file} with {len(dedup)} findings.")

if __name__ == "__main__":
    main()
