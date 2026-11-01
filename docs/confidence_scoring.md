# REDLOOP Confidence Scoring & Provenance Architecture

This document formalizes the multi-factor transparent confidence modeling, provenance completeness scoring, and verification lifecycle enforced throughout REDLOOP.

---

## 1. Mathematical Confidence Model

REDLOOP exposes two confidence values. `confidence` is the legacy six-factor
observation score retained for API compatibility. `confidence_evidence` is the
current evidence-based score and is labelled `HEURISTIC_CONFIDENCE` until a
calibration dataset proves otherwise.

$$C_{evidence} = 0.30S + 0.20A + 0.20I + 0.15F + 0.15C$$

| Factor | Name | Weight | Definition |
| :--- | :--- | :---: | :--- |
| **$S$** | **Source Reliability** | 0.30 | Trust standing of the originating provider or tool. |
| **$A$** | **Source Agreement** | 0.20 | Independent corroboration. A single source scores `0.0` agreement and is labelled `SINGLE_SOURCE`. |
| **$I$** | **Evidence Integrity** | 0.20 | Canonical SHA-256 verification of the evidence payload. |
| **$F$** | **Freshness** | 0.15 | Exponential half-life decay for the observation type. |
| **$C$** | **Provenance Completeness** | 0.15 | Fraction of applicable required provenance fields present. |

If source reliability or most applicable factors are unavailable, the result is
`INSUFFICIENT_EVIDENCE` with a null score rather than a fabricated number.
Every result carries `calibration_status: NOT_CALIBRATED` until labelled
outcomes support a Brier score and expected calibration error.

### Legacy six-factor score

The legacy score is a bounded real number in $[0.0, 1.0]$ evaluated via a weighted linear combination of six independent factors:

$$C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X$$

### Factor Definitions & Weights

| Factor | Name | Weight | Range | Definition |
| :--- | :--- | :---: | :---: | :--- |
| **$S$** | **Source Reliability** | 0.25 | $0.0 - 1.0$ | Credibility and authoritative standing of the reporting provider or tool. |
| **$D$** | **Direct Observation** | 0.25 | $0.0 - 1.0$ | Direct socket/packet observation versus second-hand aggregation or inference. |
| **$I$** | **Independent Corroboration** | 0.20 | $0.0 - 1.0$ | Degree of agreement across two or more distinct detection mechanisms. |
| **$F$** | **Freshness Decay** | 0.10 | $0.0 - 1.0$ | Time-decay coefficient based on observation age and target volatility. |
| **$P$** | **Parser Validation** | 0.10 | $0.0 - 1.0$ | Strict grammar, schema, and cryptographic checksum validation of raw output. |
| **$X$** | **Cross-Source Consistency** | 0.10 | $0.0 - 1.0$ | Absence of contradictory records in checked sources. |

---

## 2. Source Reliability ($S$) Hierarchy

Different sources have inherently different failure modes and trust boundaries:

1. **Native Local / Scoped Execution ($S = 0.95 - 1.00$):**
   - Direct socket probes (`ss`, raw TCP connect, authenticated Nmap scan).
   - Local kernel inspection (`uname`, `id`, process table).
2. **Authoritative First-Party Services ($S = 0.85 - 0.90$):**
   - Registry RDAP/WHOIS servers (ARIN, RIPE, APNIC).
   - Official DNS root and authoritative nameservers.
3. **Reputable Threat Intel Gateways ($S = 0.70 - 0.80$):**
   - AbuseIPDB, Shodan, VirusTotal, crt.sh certificate logs.
4. **Third-Party Passive Repositories ($S = 0.50 - 0.65$):**
   - Aggregated breach compilations, web search snippets.
5. **Generative Model Inference ($S = 0.30 - 0.45$):**
   - LLM reasoning or synthetic deductions without tool-collected evidence.

---

## 3. Freshness Decay ($F$) Formulation

Observations become stale as network conditions change. REDLOOP applies exponential decay to observation freshness:

$$F(t) = 2^{-\Delta t / t_{1/2}} = \exp\left(-\lambda \cdot \Delta t\right), \quad \lambda = \frac{\ln 2}{t_{1/2}}$$

Where $\Delta t$ is the elapsed time since observation and $t_{1/2}$ is the configured half-life for the observation type:

| Observation type | Half-life |
| :--- | :--- |
| IP classification, public username presence | 24 hours |
| DNS answers, PTR records, default fallback | 1 hour |
| TLS certificates, email exposure metadata | 7 days |
| RDAP registration, ASN allocation, phone numbering | 30 days |
| Static file metadata | 365 days |

The score always follows the formula. The companion status is `FRESH` only
inside a small window of $\max(1\text{ s}, 1\% \cdot t_{1/2})$ and `DECAYED`
outside it; `decay_fraction = 1 - F`. A malformed timestamp yields
`NOT_APPLICABLE` with a null score.

---

## 4. Provenance Completeness ($PC$)

Every finding reported in REDLOOP must possess complete provenance metadata. Provenance Completeness is evaluated across five mandatory fields:

$$PC = \frac{\text{has\_source} + \text{has\_timestamp} + \text{has\_method} + \text{has\_evidence} + \text{has\_confidence}}{5}$$

1. **Source (`source`):** The exact tool, binary, or provider originating the observation (e.g. `nmap`, `rdap`).
2. **Timestamp (`timestamp`):** ISO-8601 UTC timestamp of collection.
3. **Method (`method`):** Explicit collection technique (e.g. `tcp_syn_scan`, `tls_handshake`).
4. **Evidence Reference (`evidence_id` / `evidence_hash`):** Cryptographic SHA-256 digest linking finding to immutable audit record.
5. **Confidence (`confidence`):** Valid numeric score in $[0.0, 1.0]$.

Findings with $PC < 1.0$ are rejected by the strict reporting pipeline.

---

## 5. Strict Verification Boundary (Non-Negotiable Rule)

> **CRITICAL RULE:**
> Under no circumstances may an inference or deduction be marked `VERIFIED` without raw, verifiable evidence.
> Even if an inference achieves a calculated confidence of $1.0$, its verification state MUST strictly remain `INFERRED`.

### Explicit Verification States

| State | Definition | Trigger Conditions |
| :--- | :--- | :--- |
| **`OBSERVED`** | Directly measured by an authorized security tool or socket probe. | Direct observation with raw evidence payload. |
| **`VERIFIED`** | Direct observation confirmed with cryptographic proof and high confidence. | $D = 1.0$, Valid SHA-256 evidence, $C \ge 0.90$. |
| **`INFERRED`** | Algorithmic, statistical, or LLM deduction. | Derived finding without direct socket observation. |
| **`UNVERIFIED_LOCALLY`** | Reported by external provider but not confirmed on local target. | Passive OSINT finding lacking active confirmation. |
| **`NOT_FOUND_IN_CHECKED_SOURCES`** | Queried sources responded with zero matches. | Clean negative response from all queried sources. |
| **`PROVIDER_NOT_CONFIGURED`** | Source or tool unavailable/unconfigured. | Missing API token, binary not installed. |
| **`RATE_LIMITED`** | Upstream provider issued HTTP 429 or quota limit. | Rate-limit response captured in audit log. |
| **`FAILED`** | Network timeout, socket error, or execution fault. | Tool or socket error with stderr captured. |

---

## 6. Accuracy, Cache, and Calibration States

Undefined classification metrics return `None` with `NOT_APPLICABLE`; they are
never reported as `0.0`. Per-class, macro, weighted, confusion-matrix, Brier,
and expected-calibration-error values are computed only when denominators and
labelled samples exist. Expected calibration error requires at least 10 labelled
samples; below that it returns `NOT_CALIBRATED`. A computed error is reported
with `status: COMPUTED` and `calibration_claim: NOT_CALIBRATED`, because
measuring calibration is not proof that the model is calibrated.

Cache results use the canonical states `LIVE`, `CACHED_FRESH`, `CACHED_STALE`,
`EXPIRED`, `CACHE_MISS`, and `OFFLINE_RESULT`. The legacy `cache_status`
(`LIVE`, `CACHED`, `STALE`) is preserved for existing clients. A stale entry is
always labelled `CACHED_STALE` and carries the failed-live-lookup reason.

Relationship edges created from OSINT results must carry a non-empty `source`,
`method`, `timestamp`, and `evidence_reference`; otherwise the edge is not
created. Related entities carry the same provenance fields and their own
verification state.

## 7. Low-Confidence Review Queue (&lt; 0.50 Triage)

Any intent classification or automated finding with $C < 0.50$ is quarantined into the **Low-Confidence Review Queue**:

1. **Automatic Ingestion:** Orchestrator logs borderline or ambiguous requests directly into `data/confidence_review.sqlite`.
2. **Fail-Safe Fallback:** The engine degrades gracefully (e.g. defaulting to safe `GENERAL_CHAT` rather than running intrusive security tools).
3. **Operator Validation:** Human operator inspects pending items via `GET /api/system/low-confidence-queue` or the System Health dashboard panel.
4. **Resolution Audit:** Operators may approve, override, or dismiss items via `POST /api/system/low-confidence-queue/{id}/resolve`. All resolutions are cryptographically logged with reviewer identity and timestamp.

## 8. Threat-Intelligence Workspaces

### VirusTotal v3

`VirusTotalClient` returns explicit states: `LIVE_RESULT`, `CACHED_RESULT`,
`RATE_LIMITED`, `API_UNAVAILABLE`, `INVALID_INPUT`, `ANALYSIS_PENDING`, and
`NOT_FOUND`. A missing key, auth failure, rate limit, or transport failure is
never reported as clean. Only successful and explicit `NOT_FOUND` responses are
cached. File uploads are opt-in, capped at 32 MiB, and require the exact
`UPLOAD_TO_VIRUSTOTAL` consent token.

`detection_ratio` is `malicious / verdict-returning engines`; `engine_coverage`
reports verdict-returning engines over total applicable engines. A 1/1 ratio is
visibly different from 60/70, and neither is a probability of maliciousness.
Evidence hashes exclude cache and fetch timestamps, so they verify for both live
and cached observations.

### Email footprint

`EmailFootprintEngine` uses public sources only and never probes registration,
login, or password-reset endpoints. External adapters are disabled by default.
A name, username, or avatar similarity never confirms an identity. Confirmation
requires an explicit authoritative public association or at least two
independent strong public sources. Breach metadata is minimised and redacted.
Confidence is labelled `HEURISTIC_CONFIDENCE` and `NOT_CALIBRATED`.

### Identity correlation

`IdentityCorrelationStore` merges only exact shared identifiers or explicit
correlation keys. Classifications are `CONFIRMED_PUBLIC_ASSOCIATION`,
`STRONG_PUBLIC_MATCH`, `POSSIBLE_MATCH`, `UNVERIFIED`,
`NOT_PUBLICLY_VERIFIABLE`, and `CONFLICTING_EVIDENCE`. Conflicting evidence
returns a null confidence instead of an averaged score. Analyst decisions are
persisted as `CONFIRMED`, `REJECTED`, or `UNVERIFIED`, appended to a review
history, and written to the audit ledger.

### External audit checkpoint

`AuditCheckpointStore` signs the verified audit head with HMAC-SHA256 in a file
outside the SQLite database. It detects modification, truncation, replacement,
and rollback; `CHECKPOINT_VALID_UNANCHORED_TAIL` means events were appended after
the last checkpoint. Checkpoint creation is always explicit. The residual
limitation is documented: atomic replacement of the database, checkpoint,
sequence sidecar, and key cannot be detected without an external anchor.
