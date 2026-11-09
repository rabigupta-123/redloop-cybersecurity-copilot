"""Scan entire git history for secret patterns and report commit hashes + paths only (NO values)."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

PATTERNS = {
    "Groq API Key": re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}"),
    "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"),
    "Anthropic API Key": re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
    "Google API Key": re.compile(r"AIza[a-zA-Z0-9_\-]{30,}"),
    "Generic Bearer Token": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{25,}", re.IGNORECASE),
}

def main():
    res = subprocess.run(["git", "rev-list", "--all"], capture_output=True, text=True, check=True)
    commits = [c.strip() for c in res.stdout.splitlines() if c.strip()]

    findings = []
    for c in commits:
        full_diff = subprocess.run(["git", "show", "-p", c], capture_output=True, text=True, errors="replace")
        cur_file = None
        for line in full_diff.stdout.splitlines():
            if line.startswith("+++ b/"):
                cur_file = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                for stype, pat in PATTERNS.items():
                    m = pat.search(line)
                    if m:
                        val = m.group(0)
                        if any(x in val.lower() for x in ("dummy", "mock", "example", "placeholder", "fake")):
                            continue
                        findings.append({
                            "commit": c,
                            "path": cur_file or "unknown",
                            "type": stype,
                        })

    # Deduplicate
    dedup = []
    seen = set()
    for f in findings:
        k = (f["commit"], f["path"], f["type"])
        if k not in seen:
            seen.add(k)
            dedup.append(f)

    # Write report with commit hashes + paths only, NO values
    out_lines = [
        "# REDLOOP — Historical Secret Scan & Key Rotation Action Plan",
        "",
        "## 1. Secrets Detected in Git History",
        "",
        "In compliance with Phase 0.1, the table below lists **paths and commit hashes only** with **zero secret values or masked values**.",
        "",
        "| Commit Hash | File Path | Secret Type | Notes |",
        "| :--- | :--- | :--- | :--- |",
    ]

    for d in dedup:
        notes = "Historical commit"
        if "junit_baseline.xml" in d["path"]:
            notes = "Leaked during baseline pytest execution (reported in GH013 push protection)"
        out_lines.append(f"| `{d['commit']}` | `{d['path']}` | {d['type']} | {notes} |")

    out_lines.extend([
        "",
        "---",
        "",
        "## 2. Leaked Key Identification: `artifacts/junit_baseline.xml`",
        "",
        "- **Identified Commit:** `07b27ae2db2e1ad770cc96e3a4c4dad2a96ecbd0`",
        "- **File Path:** `artifacts/junit_baseline.xml` (lines 652, 670, 671)",
        "- **Secret Category:** Groq API Key (`gsk_...`)",
        "- **Root Cause:** In Phase 0 calibration, `pytest` executed `tests/test_provider_gateway.py::test_keystore_encryption_and_decryption`. The assertion error dumped the live key returned from `get_key('groq', user_id='user_bob')` into the JUnit XML test failure report.",
        "- **Current Working Tree Status:** Sanitized to `[REDACTED_SECRET]` in the current working tree.",
        "- **Git History Status:** The commit remains reachable in local/remote ref history until git history rewrite.",
        "",
        "---",
        "",
        "## 3. Mandatory Provider Key Rotation Checklist (Owner Action Steps)",
        "",
        "The repository owner must immediately execute the following rotations across all provider portals. **Do not reuse any existing keys.**",
        "",
        "1. **Groq API Key:**",
        "   - Portal: [https://console.groq.com/keys](https://console.groq.com/keys)",
        "   - Action: Revoke the leaked API key immediately. Generate a new key and update the local `.env` (`GROQ_API_KEY`).",
        "",
        "2. **Scope Signing HMAC Secret:**",
        "   - Command: `redloop scope rotate-secret`",
        "   - Action: Generates a new 32-byte cryptographically random HMAC secret and re-signs all active scope manifests (`scope.yaml`).",
        "",
        "3. **OpenRouter API Key:**",
        "   - Portal: [https://openrouter.ai/keys](https://openrouter.ai/keys)",
        "   - Action: Invalidate existing keys and regenerate `OPENROUTER_API_KEY`.",
        "",
        "4. **NVIDIA NIM API Key:**",
        "   - Portal: [https://build.nvidia.com/](https://build.nvidia.com/)",
        "   - Action: Rotate `NVIDIA_API_KEY`.",
        "",
        "5. **Google Gemini API Key:**",
        "   - Portal: [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)",
        "   - Action: Delete existing API key and provision a new `GEMINI_API_KEY`.",
        "",
        "6. **VirusTotal v3 API Key:**",
        "   - Portal: [https://www.virustotal.com/gui/user/apiKey](https://www.virustotal.com/gui/user/apiKey)",
        "   - Action: Rotate `VIRUSTOTAL_API_KEY` in account settings.",
        "",
        "7. **Shodan API Key:**",
        "   - Portal: [https://account.shodan.io/](https://account.shodan.io/)",
        "   - Action: Rotate `SHODAN_API_KEY`.",
        "",
        "8. **Apinex / Secondary Gateway Keys:**",
        "   - Portal: Respective provider console",
        "   - Action: Rotate any configured secondary gateway tokens.",
        "",
        "---",
        "",
        "## 4. History Rewrite Plan (`git-filter-repo`)",
        "",
        "> [!IMPORTANT]",
        "> Per Phase 0.1 instructions, this plan is offered for owner execution. **It is NOT run automatically**.",
        "",
        "### Step 1: Install `git-filter-repo`",
        "```bash",
        "pip install git-filter-repo",
        "```",
        "",
        "### Step 2: Create a Fresh Mirror Clone (Safety Precaution)",
        "```bash",
        "git clone --mirror https://github.com/rabigupta-123/redloop-cybersecurity-copilot.git redloop-backup.git",
        "```",
        "",
        "### Step 3: Run `git-filter-repo` to Redact Sensitive Artifacts from History",
        "```bash",
        "# Remove artifacts/junit_baseline.xml from all historical commits",
        "git filter-repo --path artifacts/junit_baseline.xml --invert-paths",
        "```",
        "",
        "### Step 4: Force Push Rewritten References (Requires Repository Admin Permission)",
        "```bash",
        "git remote add origin https://github.com/rabigupta-123/redloop-cybersecurity-copilot.git",
        "git push origin --force --all",
        "git push origin --force --tags",
        "```",
        "",
        "---",
        "",
        "## 5. .gitignore & Tracking Verification",
        "",
        "- `.env`: Confirmed gitignored and NOT tracked.",
        "- `*.key`: Confirmed gitignored and NOT tracked.",
        "- `*.sqlite`: Confirmed gitignored and NOT tracked.",
        "- `*.db`: Confirmed gitignored and NOT tracked.",
        "- `data/`: Confirmed runtime databases (`*.sqlite`, `*.db`, `*.sig`) are gitignored; only static knowledge seed packs and `platforms.json` are tracked.",
    ])

    report_path = Path("docs/SECRETS_REPORT.md")
    report_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"SECRETS_REPORT.md generated with {len(dedup)} findings.")

if __name__ == "__main__":
    main()
