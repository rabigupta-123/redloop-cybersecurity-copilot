# REDLOOP — Phase 6.1 Threat Intelligence Assurance & Security Audit

**Audit Date:** 2026-11-04  
**Auditor:** REDLOOP Security & Quality Engineering Lead  
**Git Base Commit:** `6137d01` (`feat(threat-hunting): add ATT&CK mapping and detection engineering`)  
**Application Target:** `http://127.0.0.1:8765/`  
**Execution Environment:** Windows 11 (Python 3.12, Uvicorn Daemon PID 9348)  
**Baseline Test Results:** 227 passed / 227 ran (100% pass across core test suites)  

---

## 1. Verified Baseline Facts & Git State

1. **Git Repository Status:**
   - Active branch: `main`
   - Remote tracking: `origin/main` (synced at `6137d01`)
   - Working tree: Clean (zero uncommitted or untracked changes at start of audit)
2. **Runtime Verification:**
   - Background server process (PID 9348) verified running and responding to HTTP requests on `http://127.0.0.1:8765/`
   - Verified live endpoints:
     - `GET /api/hunting/attack/tactics` (HTTP 200, 14 tactics)
     - `GET /api/hunting/sigma/matrix` (HTTP 200, 6 supported modifiers)
     - `POST /api/hunting/query/plan` (HTTP 200, explainable query plan)
     - `POST /api/hunting/chain/reconstruct` (HTTP 200, chain correlation)
3. **Automated Test Baseline:**
   - `tests/test_phase*.py`: 211 passed in 60.55s
   - `tests/test_target_isolation.py`: 10 passed in 10.37s
   - `tests/test_workbench.py`: 6 passed in 8.85s
   - Total verified passing tests: 227 passed, 0 failures.

---

## 2. Phase 6 Implementation Audit & Gap Analysis

### 2.1 MITRE ATT&CK Catalog Integrity (`attack_mapping.py`)
- **Verified Facts:**
  - Catalog currently covers all 14 Enterprise Tactics (`TA0043` through `TA0040`) in canonical sequence.
  - Contains 26 curated techniques and sub-techniques.
- **Defects & Gaps Identified:**
  - Previous documentation referred to 20+ techniques as the "authoritative dataset", which could be misinterpreted as complete Enterprise coverage (Enterprise ATT&CK contains >600 techniques and sub-techniques).
  - Missing explicit catalog versioning metadata (`DATASET_VERSION = "v15.1"`, `RETRIEVAL_DATE = "2024-10-31"`, `CATALOG_SCOPE = "Enterprise ATT&CK Priority Subset"`).
  - Lack of formal distinction between `VALID`, `DEPRECATED` (e.g. `T1086` PowerShell -> revoked/superseded by `T1059.001`), and `INVALID` technique IDs.
  - Heuristic event-pattern mappings were returned alongside authoritative detection rule mappings without an explicit `is_inferred: bool` or `mapping_type` flag.
  - Absence of platform applicability metadata (e.g. `platforms: ["Windows", "Linux", "macOS"]`).

### 2.2 Sigma Engine Conformance & Regex Safety (`sigma_engine.py`)
- **Verified Facts:**
  - Strict YAML parsing via `yaml.safe_load`.
  - Condition evaluator uses pure AST / Shunting-Yard token evaluation without `eval()`, preventing arbitrary code execution.
  - Supports field modifiers: `|contains`, `|startswith`, `|endswith`, `|re`, `|all`, and `|base64offset`.
- **Defects & Gaps Identified:**
  - `evaluate_rule` returned `False, None` when a rule was invalid, unparsed, or malformed, silently conflating unsupported rules with non-matching rules.
  - Regex modifier (`|re`) currently relies on Python's synchronous `re.search` after basic syntactic heuristics (`(\+|\*)\s*(\+|\*)`). While this catches simple nested quantifiers, adversarial ReDoS patterns with complex grouping or lookaround can still cause catastrophic backtracking on long inputs.
  - Missing bounded input length and pattern length checks during regex evaluation.
  - Missing execution timeout/thread-isolation wrapper for regex evaluations.
  - Missing rule UUID duplicate detection when evaluating rule sets.
  - Missing versioned corpus of representative valid and invalid test rules.

### 2.3 Playbook Approval Capability Security (`soc_playbooks.py`)
- **Verified Facts:**
  - Cryptographically random 256-bit entropy tokens (`rl-cap-*`) issued on step approval.
  - SHA-256 hash stored in SQLite; raw secrets never persisted.
  - 15-minute TTL enforced.
  - Atomic one-time consumption prevents basic replay.
- **Defects & Gaps Identified:**
  - `validate_and_consume` only bound the token to `playbook_id` and `step_id`, but did not enforce cryptographic binding to the exact action command and parameters (`action_command` or canonical parameter hash). If parameters were altered between approval and execution, the token was still consumed.
  - Error messages in edge cases could echo token fragments if not strictly sanitized.
  - Approval capability must be explicitly documented and treated as a "local operator approval capability" rather than cryptographic proof of an authenticated user identity, since REDLOOP runs locally without external IdP authentication.

### 2.4 Threat-Hunting Query Security (`threat_hunting.py`)
- **Verified Facts:**
  - Natural language parsing generates an explainable AST query plan preview with cost estimation (`LOW`, `MEDIUM`, `HIGH`).
  - Strict maximum safety limit clamped to 1000 records.
  - In-memory event filtering prevents SQL injection against persistent tables.
- **Defects & Gaps Identified:**
  - Lacked an explicit strict allowlist of queried fields (`ALLOWED_FIELDS`) and operators (`ALLOWED_OPERATORS`).
  - Lacked query complexity limits (maximum filter clauses, maximum query length).
  - Missing server-side time-range validation to reject impossible timestamps (e.g. future timestamps or malformed dates).
  - Missing pagination support (`offset` parameter) for large query results.
  - Did not enforce explicit target/session context isolation, creating the risk of accidental cross-investigation data leakage.

### 2.5 Attack Chain Model Accuracy (`attack_chain.py`)
- **Verified Facts:**
  - Reconstructs chronological sequence across 13 kill-chain stages.
  - Explicitly categorizes steps into `OBSERVED` vs `INFERRED`.
- **Defects & Gaps Identified:**
  - The reconstructor automatically inserted synthetic `inferred_steps` for all intermediate gaps, violating the requirement: *"A missing stage must not be automatically filled."*
  - Automatically declared entry point candidates even when Initial Access was unobserved, violating: *"Initial access and impact must not be asserted without evidence."*
  - Crown jewel targets were heuristically assumed even without collection/exfiltration/impact evidence.
  - Did not preserve contradictory evidence (e.g. reversed timestamps or contradictory source identities).

---

## 3. Corrective Plan for Phase 6.1

| Component | Target File | Corrective Action |
| :--- | :--- | :--- |
| **B1. ATT&CK Integrity** | `attack_mapping.py` | Add catalog version metadata, deprecated ID catalog with migration pointers, platform metadata, `TechniqueStatus` enum, and explicit `is_inferred` / `mapping_type` flags. |
| **B2. Sigma Conformance** | `sigma_engine.py` | Implement thread-isolated regex execution with strict 100ms timeout; bound input & pattern lengths; distinguish unparsed/unsupported/malformed rule errors from non-matches; add rule UUID duplicate check. |
| **B3. Capability Security** | `soc_playbooks.py` | Bind approval tokens to exact `action_command` and canonical parameter hash; reject parameter modifications; audit redaction; clarify local operator scope. |
| **B4. Query Security** | `threat_hunting.py` | Add strict field/operator allowlists; query length & clause complexity limits; time-range validation; pagination support (`offset`); session context isolation. |
| **B5. Attack Chain Accuracy** | `attack_chain.py` | Stop automatically injecting inferred steps into gaps (record gaps as telemetry gaps only); do not assert entry point / impact without evidence; preserve contradictory evidence. |
| **B6. Report Integrity** | `workbench.py` & models | Ensure reports accurately mirror stored event IDs, Sigma match details, and explicit evidence provenance. |

---

## 4. Acceptance Criteria for Phase 6.1 Gate

Phase 7 development must not commence until:
1. `tests/test_phase6_1_assurance.py` is created with tests covering B1–B6 scenarios and passing 100%.
2. Existing Phase 1–6 tests continue passing without regression.
3. No critical or high-severity security defect remains in threat intelligence, rule evaluation, or capability token enforcement.
