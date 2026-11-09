# REDLOOP — Historical Secret Scan & Key Rotation Action Plan

## 1. Secrets Detected in Git History

In compliance with Phase 0.1, the table below lists **paths and commit hashes only** with **zero secret values or masked values**.

| Commit Hash | File Path | Secret Type | Notes |
| :--- | :--- | :--- | :--- |
| `01ac0a1ec7900994ad6fe97278d7da5cfe8eb428` | `tests/test_ai_tool_agent_hardening.py` | Groq API Key | Historical commit |
| `01ac0a1ec7900994ad6fe97278d7da5cfe8eb428` | `tests/test_ai_tool_agent_hardening.py` | OpenAI API Key | Historical commit |
| `75a242581e129e3924fc0fa648d430f87ed2be6a` | `artifacts/junit_baseline.xml` | Groq API Key | Leaked during baseline pytest execution (reported in GH013 push protection) |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_audit_verify.py` | Groq API Key | Historical commit |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_final_redesign.py` | OpenAI API Key | Historical commit |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_final_redesign.py` | Anthropic API Key | Historical commit |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_hardening_items.py` | Groq API Key | Historical commit |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_pipeline_hardening.py` | Groq API Key | Historical commit |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_pipeline_hardening.py` | OpenAI API Key | Historical commit |
| `b9ff376eb39a3e2d69c83428fbad4c5f1dae1f2f` | `tests/test_provider_gateway.py` | Groq API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_audit_verify.py` | Groq API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_final_redesign.py` | OpenAI API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_final_redesign.py` | Anthropic API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_hardening_items.py` | Groq API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_pipeline_hardening.py` | Groq API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_pipeline_hardening.py` | OpenAI API Key | Historical commit |
| `b1b512fb4a5eb7d0795c83d47956747f80efd690` | `tests/test_provider_gateway.py` | Groq API Key | Historical commit |

---

## 2. Leaked Key Identification: `artifacts/junit_baseline.xml`

- **Identified Commit:** `07b27ae2db2e1ad770cc96e3a4c4dad2a96ecbd0`
- **File Path:** `artifacts/junit_baseline.xml` (lines 652, 670, 671)
- **Secret Category:** Groq API Key (`gsk_...`)
- **Root Cause:** In Phase 0 calibration, `pytest` executed `tests/test_provider_gateway.py::test_keystore_encryption_and_decryption`. The assertion error dumped the live key returned from `get_key('groq', user_id='user_bob')` into the JUnit XML test failure report.
- **Current Working Tree Status:** Sanitized to `[REDACTED_SECRET]` in the current working tree.
- **Git History Status:** The commit remains reachable in local/remote ref history until git history rewrite.

---

## 3. Mandatory Provider Key Rotation Checklist (Owner Action Steps)

The repository owner must immediately execute the following rotations across all provider portals. **Do not reuse any existing keys.**

1. **Groq API Key:**
   - Portal: [https://console.groq.com/keys](https://console.groq.com/keys)
   - Action: Revoke the leaked API key immediately. Generate a new key and update the local `.env` (`GROQ_API_KEY`).

2. **Scope Signing HMAC Secret:**
   - Command: `redloop scope rotate-secret`
   - Action: Generates a new 32-byte cryptographically random HMAC secret and re-signs all active scope manifests (`scope.yaml`).

3. **OpenRouter API Key:**
   - Portal: [https://openrouter.ai/keys](https://openrouter.ai/keys)
   - Action: Invalidate existing keys and regenerate `OPENROUTER_API_KEY`.

4. **NVIDIA NIM API Key:**
   - Portal: [https://build.nvidia.com/](https://build.nvidia.com/)
   - Action: Rotate `NVIDIA_API_KEY`.

5. **Google Gemini API Key:**
   - Portal: [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
   - Action: Delete existing API key and provision a new `GEMINI_API_KEY`.

6. **VirusTotal v3 API Key:**
   - Portal: [https://www.virustotal.com/gui/user/apiKey](https://www.virustotal.com/gui/user/apiKey)
   - Action: Rotate `VIRUSTOTAL_API_KEY` in account settings.

7. **Shodan API Key:**
   - Portal: [https://account.shodan.io/](https://account.shodan.io/)
   - Action: Rotate `SHODAN_API_KEY`.

8. **Apinex / Secondary Gateway Keys:**
   - Portal: Respective provider console
   - Action: Rotate any configured secondary gateway tokens.

---

## 4. History Rewrite Plan (`git-filter-repo`)

> [!IMPORTANT]
> Per Phase 0.1 instructions, this plan is offered for owner execution. **It is NOT run automatically**.

### Step 1: Install `git-filter-repo`
```bash
pip install git-filter-repo
```

### Step 2: Create a Fresh Mirror Clone (Safety Precaution)
```bash
git clone --mirror https://github.com/rabigupta-123/redloop-cybersecurity-copilot.git redloop-backup.git
```

### Step 3: Run `git-filter-repo` to Redact Sensitive Artifacts from History
```bash
# Remove artifacts/junit_baseline.xml from all historical commits
git filter-repo --path artifacts/junit_baseline.xml --invert-paths
```

### Step 4: Force Push Rewritten References (Requires Repository Admin Permission)
```bash
git remote add origin https://github.com/rabigupta-123/redloop-cybersecurity-copilot.git
git push origin --force --all
git push origin --force --tags
```

---

## 5. .gitignore & Tracking Verification

- `.env`: Confirmed gitignored and NOT tracked.
- `*.key`: Confirmed gitignored and NOT tracked.
- `*.sqlite`: Confirmed gitignored and NOT tracked.
- `*.db`: Confirmed gitignored and NOT tracked.
- `data/`: Confirmed runtime databases (`*.sqlite`, `*.db`, `*.sig`) are gitignored; only static knowledge seed packs and `platforms.json` are tracked.
