<div align="center">

# 🛡️ RedLoop Cybersecurity Copilot

**Autonomous Security Assessment, Threat Intelligence Triage & SOC Investigation Workbench**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Unified_Console-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Automated Release](https://img.shields.io/badge/GitHub-Automated_Release-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/rabigupta-123/redloop-cybersecurity-copilot/releases)
[![Tests Passed](https://img.shields.io/badge/Tests-1%2C094_Passed_(100%25)-2EA44F?style=for-the-badge&logo=pytest&logoColor=white)](#-empirical-quality--verification-benchmarks)
[![Scope Breach Rate](https://img.shields.io/badge/SBR-0.0000_(Zero_Breaches)-blueviolet?style=for-the-badge)](#-security-architecture--fail-closed-boundaries)
[![License: MIT](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](pyproject.toml)

*Locally run, cryptographically scope-limited cybersecurity engineering platform and AI copilot for authorized penetration testing, threat hunting, OSINT correlation, learning labs, and CTFs.*

[Overview](#-overview) •
[Visual Tour](#-visual-tour) •
[Key Capabilities](#-key-capabilities) •
[System Architecture](#-system-architecture) •
[Quickstart](#-quickstart) •
[CLI & API Reference](#-cli--api-reference) •
[Security Boundaries](#-security-architecture--fail-closed-boundaries) •
[Quality Benchmarks](#-empirical-quality--verification-benchmarks) •
[Automated Release](#-automated-release--cicd)

</div>

---

## 🎯 Overview

**RedLoop** bridges autonomous offensive operations, forensic triage, and SOC engineering with a **machine-enforced, fail-closed security architecture**:

- **Cryptographic Scope Contract (`scope.yaml`)**: Every IP, CIDR, port, and authorized action is governed by an `HMAC-SHA256` signed manifest. Denied commands spawn zero subprocesses, emit zero network packets, and log audit violations with exit code `126`.
- **Immutable Hash-Chained Audit Ledger**: Every operation is recorded in a cryptographic `SHA-256` audit chain protected by database-level SQLite triggers (`BEFORE UPDATE/DELETE RAISE(ABORT)`), with external HMAC checkpoint anchoring.
- **Senior AI Security Copilot**: Grounded in **68+ curated security packs** (`data/knowledge/seed/`) indexed via BM25 RAG. Follows a resilient inference failover chain (**Local Ollama** $\rightarrow$ **Groq** $\rightarrow$ **OpenRouter** $\rightarrow$ **Deterministic Offline Engine**) that honestly refuses unvetted queries rather than hallucinating.
- **Deep OSINT & Indicator Triage**: 8 formal verification states, multi-factor confidence scoring ($C = 0.25S + 0.25D + 0.20I + 0.10F + 0.10P + 0.10X$), a 32-platform reconnaissance catalog with soft-404 detection, and 24-hour SQLite caching.
- **Modular Workbench Architecture**: 233 active REST and WebSocket endpoints organized into 9 domain routers (`assets`, `copilot`, `ctf`, `diagnostics`, `integrations`, `investigations`, `reporting`, `soc`, `shared`).
- **Loopback-Only Binding Invariant**: The application strictly refuses to bind on public interfaces, enforcing `127.0.0.1` unless explicitly authorized via `REDLOOP_ALLOW_REMOTE=1` and operator token authentication.

---

## 📸 Visual Tour

### Unified Command Center (Dark & Light Themes)

The RedLoop Unified Console (`/`) provides real-time visibility into authorized scopes, assessment telemetry, cryptographic audit integrity, runtime tools, and live investigations.

| Dark Theme (`overview-dark-desktop.png`) | Light Theme (`overview-light-desktop.png`) |
| :---: | :---: |
| ![RedLoop Console Dark Mode](artifacts/ui/overview-dark-desktop.png) | ![RedLoop Console Light Mode](artifacts/ui/overview-light-desktop.png) |

---

### AI Security Copilot & Contextual Chat

Multi-mode assistant supporting **Senior Cybersecurity Copilot**, **Forensic Log Triage** (auto-routing Sysmon XML, Linux `auth.log`, PCAP summaries), **Offline CTF Triage**, and **Report Explainer** with verified citations.

| Unified Console Chat (`chat-light-desktop.png`) | Standalone Copilot View (`standalone-chat-light.png`) |
| :---: | :---: |
| ![RedLoop Unified Chat](artifacts/ui/chat-light-desktop.png) | ![RedLoop Standalone Chat](artifacts/ui/standalone-chat-light.png) |

---

### Security Workbench & SOC Telemetry

Execute Red/Blue/Purple track workflows, inspect 3D attack-surface graph models, approve SOAR playbooks with operator tokens, and audit real-time provider token consumption.

| Security Workbench (`workbench-dark-desktop.png`) | Performance & Usage Telemetry (`performance-dark-desktop.png`) |
| :---: | :---: |
| ![RedLoop Security Workbench](artifacts/ui/workbench-dark-desktop.png) | ![RedLoop Performance Telemetry](artifacts/ui/performance-dark-desktop.png) |

---

## ⚡ Key Capabilities

### 1. Terminal Engine & Scope Gate (S1)
- **Tokenization & Metacharacter Defense**: Commands parsed strictly via `shlex.split()` without spawning intermediate shells (`cmd.exe` or `powershell.exe`). All shell operators (`;`, `&`, `|`, `` ` ``, `$()`, `>`, `<`, newlines) are rejected with return code `126`.
- **Approved Network Binaries**: Strict allowlist (`nmap`, `curl`, `wget`, `nc`, `ncat`, `ping`, `ssh`, `telnet`, `dig`, `nslookup`, `whatweb`, `nikto`, `gobuster`, `nuclei`, `tshark`).
- **Anti-Obfuscation**: Decodes decimal IPv4 (`2130706433`), octal/hex IPv4, bracketed IPv6 `[::1]:port`, and strips URL userinfo (`http://user:pass@evil.com`).
- **DNS Pinning**: Resolves hostnames and validates that the resolved IP matches authorized scope prior to any subprocess creation (`validate_resolved_ip`).

### 2. Senior AI Security Copilot & Knowledge Grounding (DEF-005)
- **Multi-Provider Priority Chain**: Ollama (`qwen3:8b`) $\rightarrow$ Groq (`qwen/qwen3.8-27b`) $\rightarrow$ OpenRouter (`meta-llama/llama-3.3-70b-instruct`) $\rightarrow$ Offline Deterministic Engine.
- **RAG Context Grounding**: Synthesizes verified references with mandatory source citations (`Sources: [title — source]`). Absence of knowledge results in explicit fallback rather than fabricated citations.
- **68+ Curated Seed Knowledge Packs**: In-depth coverage across Cloud IAM, Authentication (SAML, OAuth/OIDC, Kerberos, NTLM), Web Vulnerabilities (SSRF, XXE, SQLi, CSRF, IDOR), Network Protocols (TLS, TCP 3-way handshake, DNS, ARP), and OS Hardening.
- **Log Auto-Routing**: Detects pasted Windows Sysmon XML (Events 1, 3, 7, 11, 4624, 4625, 7045), Linux `auth.log` / `pam_unix` snippets, and raw PCAP tcpdump frames, automatically routing to specialized triage engines.
- **Responsible Exploit Guidance**: Exploit queries provide root-cause analysis, proof-of-concept primitives, Sigma/YARA detection rules, and defensive remediation playbooks; weaponized payloads are strictly rejected.

### 3. Deep OSINT & Identity Intelligence
- **Formal Verification States**: `OBSERVED`, `CORROBORATED`, `INFERRED`, `UNVERIFIED`, `NOT_CHECKED`, `PROVIDER_NOT_CONFIGURED`, `RATE_LIMITED`, `FAILED`.
- **Multi-Factor Confidence**: Deterministic scoring accounting for source reliability, corroboration depth, indicator specificity, feed freshness, provider verification, and anomaly detection.
- **32-Platform OSINT Catalog**: Validates usernames and profiles across 32 platforms with exact status codes, content-length thresholds, regex extractors, and soft-404 signature heuristics (`data/osint/platforms.json`).
- **Local SQLite Cache**: Built-in 24-hour caching to eliminate rate-limit exhaustion and ensure offline repeatability.

### 4. SOAR Operator Authentication & Governance (S3, S4)
- **Operator Token Authentication**: Sensitive SOAR playbook approvals (`POST /api/soc/playbooks/{id}/approve`) require a cryptographically generated operator token (`X-Operator-Token`), with only the SHA-256 fingerprint stored in SQLite.
- **Immutable Audit Triggers**: SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers abort unauthorized tampering attempts with `RAISE(ABORT)`.
- **Detached Checkpoint Anchoring**: External HMAC checkpoint verification detects middle-row deletions, database swaps, or rollback attempts.

---

## 🏗️ System Architecture

```mermaid
flowchart TB
    subgraph Clients["Operator Surfaces"]
        CLI["RedLoop CLI<br/>(redloop ...)"]
        UI["Unified Console & Workbench<br/>(127.0.0.1:8765)"]
        Chat["Copilot Drawer & Chat<br/>(/chat)"]
    end

    subgraph SecurityGate["Security Gate & Policy Invariants (Fail-Closed)"]
        Scope["ScopeManager<br/>(HMAC-SHA256 scope.yaml)"]
        Guard["AssessmentScopeGuard<br/>(Port & DNS Pinning)"]
        TokenAuth["Operator Auth Gate<br/>(X-Operator-Token)"]
        Triggers["Audit SQLite Triggers<br/>(BEFORE UPDATE/DELETE ABORT)"]
    end

    subgraph Orchestration["Task Orchestrator & Knowledge Engine"]
        Router["Multi-Provider Chain<br/>(Ollama -> Groq -> OpenRouter -> Offline)"]
        RAG["BM25 RAG Engine<br/>(68+ Curated Security Packs)"]
        AutoRoute["Log Auto-Router<br/>(Sysmon / Linux Auth / PCAP)"]
        Workbench["Modular Workbench API<br/>(9 Domain Routers)"]
    end

    subgraph Execution["Bounded Execution Engines"]
        Term["Unified Terminal Engine<br/>(shlex Split, No Metachars)"]
        OSINT["OSINT Depth Engine<br/>(32 Platforms, Multi-Factor Conf)"]
        Forensics["Static Forensics Engine<br/>(16 MiB Cap, YARA, SHA-256)"]
        Audit["AuditLogger<br/>(SHA-256 Hash Chained)"]
    end

    CLI --> Scope
    UI --> TokenAuth --> Workbench
    Chat --> Router

    Scope --> Guard --> Term
    Workbench --> Orchestration
    Router --> RAG
    Router --> AutoRoute

    Term --> Execution
    OSINT --> Audit
    Forensics --> Audit
    Execution --> Audit
    Audit --> Triggers
```

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/rabigupta-123/redloop-cybersecurity-copilot.git
cd redloop-cybersecurity-copilot

# Install package in editable mode with development, console & recon extras
pip install -e ".[dashboard,recon,forensics,dev]"
```

### 2. Configure Environment & Sign Scope Contract

```bash
# Initialize local configuration
cp .env.example .env
cp scope.yaml.example scope.yaml

# Generate an HMAC-SHA256 signature for your scope contract
redloop scope init --in scope.yaml --out scope.yaml

# Verify target and action authorization
redloop scope check 127.0.0.1 recon
```

### 3. Generate SOAR Operator Token

```bash
# Generate and display a secure operator token for playbook approvals
redloop operator-token
```

### 4. Launch the Unified Console

```bash
# Start the local FastAPI Command Center & Workbench on http://127.0.0.1:8765
redloop report serve --port 8765
```

Navigate to **`http://127.0.0.1:8765`** in your browser:
- **`/`** — Unified Command Center (Investigations, Evidence, Topology Graph, OSINT, Threat Intel)
- **`/workbench`** — Security Workbench, 3D Attack Surface, and SOC Playbook Execution
- **`/chat`** — Standalone AI Security Copilot with RAG Grounding
- **`/performance`** — Real-Time Latency, Token Metrics, and Provider Telemetry

---

## 💻 CLI & API Reference

### Core CLI Commands

| Command | Description |
| :--- | :--- |
| `redloop scope init --in <file> --out <file>` | Cryptographically sign a `scope.yaml` manifest with `HMAC-SHA256` |
| `redloop scope check <target> <action> [--port <port>]` | Verify target & action authorization against signed scope |
| `redloop scope rotate-secret` | Rotate HMAC scope secret and re-sign active scope contracts |
| `redloop operator-token` | Generate or retrieve the active local operator approval token |
| `redloop report serve [--port 8765]` | Launch the Unified Security Console, Workbench, and Copilot API |
| `redloop report generate <target> [--output <path>]` | Generate an audited Markdown security report with SHA-256 evidence |
| `redloop recon scan <target> --port <port> [...]` | Execute scoped port reconnaissance on authorized loopback |
| `redloop recon profile <target> [--port <port> ...]` | Profile target services using bounded Nmap version detection |
| `redloop tls check <target> [--port <port>]` | Inspect TLS certificate chains, expiry, SANs, and cipher hygiene |
| `redloop web inspect <url>` | Inspect HTTP headers (`CSP`, `HSTS`, `XFO`), cookies, and disclosures |
| `redloop forensics analyze <file> [--rules-dir <dir>]` | Run bounded (`16 MiB`) static file triage, entropy, and YARA scans |
| `redloop audit verify` | Validate cryptographic integrity of the SHA-256 audit ledger |
| `redloop audit anchor --confirm` | Create an external HMAC checkpoint with detached `.sig` signature |

### Workbench Domain Routers (`src/redloop/workbench/`)

| Router Module | Domain & Responsibilities | Key Endpoints |
| :--- | :--- | :--- |
| `router_copilot.py` | Copilot, Chat Sessions & Terminal Execution | `/api/chat`, `/api/copilot/status`, `/api/terminal/execute` |
| `router_investigations.py` | 10-Stage Autonomous Investigations & Evidence | `/api/investigations`, `/api/investigations/{id}/stages` |
| `router_soc.py` | SOC Alerts, Playbooks & SOAR Approval | `/api/soc/alerts`, `/api/soc/playbooks/{id}/approve` |
| `router_integrations.py` | AI Providers & OSINT Integrations Hub | `/api/providers`, `/api/providers/{id}/test` |
| `router_diagnostics.py` | Health Probes, System Telemetry & Tokens | `/api/health`, `/api/telemetry/tokens` |
| `router_reporting.py` | Report Generation, Export & Compliance | `/api/reports/generate`, `/api/reports/export` |
| `router_assets.py` | Target Asset Topology & 3D Graph Nodes | `/api/assets`, `/api/assets/graph` |
| `router_ctf.py` | In-Memory CTF Challenges & Archive Analysis | `/api/ctf/challenges`, `/api/ctf/analyze` |

---

## 🔒 Security Architecture & Fail-Closed Boundaries

```text
                                [ INCOMING REQUEST ]
                                         │
                         ┌───────────────┴───────────────┐
                         ▼                               ▼
                 [ REST / WEB API ]              [ CLI / TERMINAL ]
                         │                               │
                 Loopback Check                  shlex Tokenization
             (127.0.0.1 or Auth Token)        (Reject ; & | ` $ > < \n)
                         │                               │
                         └───────────────┬───────────────┘
                                         ▼
                        [ S1 SCOPE VERIFICATION GATE ]
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
            Target / CIDR Check                       Port Authorization
         (Signed scope.yaml Match)                  (Explicit Port Required)
                    │                                         │
                    └────────────────────┬────────────────────┘
                                         ▼
                            [ DNS REBINDING DEFENSE ]
                        (Resolves Host -> Verifies IP)
                                         │
                    ┌────────────────────┴────────────────────┐
                    │                                         │
               [ DENIED ]                                [ ALLOWED ]
                    │                                         │
          Exit Code 126 (BLOCKED)                    Execute Authorized Action
        Zero Subprocesses Created                   Record SHA-256 Audit Link
         Audit Ledger Row Written                  Check SQLite Immutability
```

1. **Fail-Closed Gate**: Denied operations return exit code `126`, spawn zero subprocesses, and emit zero packets.
2. **Loopback-Only Invariant**: Default binding is hard-locked to `127.0.0.1`. Remote binding requires `REDLOOP_ALLOW_REMOTE=1` and operator credentials.
3. **No Code Fabrication**: Product code in `src/redloop/` contains zero synthetic mocks; all security checks execute real AST analysis, cryptographic verification, and system socket APIs.
4. **Secrets Hygiene**: Credentials (`gsk_*`, `sk-*`, `AIza*`, Bearer tokens) are automatically redacted via regex before audit persistence or UI rendering.

---

## 📊 Empirical Quality & Verification Benchmarks

All metrics reflect raw execution counts and mathematically bounded Wilson 95% confidence intervals across held-out datasets:

| Dimension / Metric | Baseline (Phase 0) | Quality Pass (Phase 8) | Delta / Target | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Total Test Suite Collected** | 1,009 tests | **1,094 tests** | +85 tests | **EXPANDED** |
| **Passed Tests** | 990 passed | **1,094 passed** | +104 passing | **100% PASS** |
| **Failed Tests** | 19 failed | **0 failed** | -19 failures | **ALL RESOLVED** |
| **Test Timeouts (>120s)** | 0 timeouts | **0 timeouts** | 0 | **ZERO FREEZES** |
| **Skipped Tests** | 0 skipped | **0 skipped** | 0 | **VERIFIED** |
| **Statement Coverage** | 69.31% overall | **72.77% (21,970 / 30,193)** | +3.46% | **EXCEEDS FLOOR** |
| **Scope Breach Rate (SBR)** | Not quantified | **0.0000 (0 / 34)** | Target: $0.0000$ | **PASSED (0.0000)** |
| **SBR Wilson 95% CI** | N/A | **[0.0000, 0.1015]** | Lower bound: $0.0000$ | **VERIFIED** |
| **Fabrication Rate (FBR)** | Not quantified | **0.0000 (0 / 68)** | Target: $0.0000$ | **PASSED (0.0000)** |
| **FBR Wilson 95% CI** | N/A | **[0.0000, 0.0535]** | Lower bound: $0.0000$ | **VERIFIED** |
| **Intent Holdout Accuracy** | Baseline: ~90.0% | **98.06% (152 / 155)** | Floor: $\ge 90.0\%$ | **EXCEEDS FLOOR** |
| **Holdout Accuracy 95% CI** | N/A | **[94.46%, 99.34%]** | Wilson CI bound | **VERIFIED** |
| **Holdout Macro-F1** | Baseline: ~0.850 | **0.9813** | Floor: $\ge 0.850$ | **EXCEEDS FLOOR** |
| **Holdout Cohen's Kappa ($\kappa$)** | N/A | **0.9794** | Near-perfect agreement | **VERIFIED** |
| **Composite Quality Index ($Q$)** | N/A | **0.8774** | Target: $\ge 0.750$ | **EXCEEDS TARGET** |
| **Copilot P95 Inference Latency** | Variable | **0.1274 ms** | Real-time offline fallback | **OPTIMAL** |
| **Total Live Application Routes** | 223 unique | **233 unique** | +10 routes (0 deleted) | **STABLE** |
| **Architecture Specification Drift**| Untracked | **0 drift** (`test_architecture_drift.py`) | AST synchronized | **VERIFIED** |
| **JavaScript Syntax Errors** | 0 production errors | **0 errors** (`node --check`) | Zero syntax defects | **VALIDATED** |

---

## 📦 Automated Release & CI/CD

RedLoop features an automated continuous release pipeline configured in [`.github/workflows/release.yml`](.github/workflows/release.yml):

- **Trigger**: Runs automatically on every push to `main` (and `fix/quality-pass`) or on git tags (`v*`).
- **Dynamic Monotonic Versioning**: Automatically parses `pyproject.toml` base version and tags each build as `v<base_version>.<github.run_number>`.
- **Automated Distribution**: Builds production Python wheels (`.whl`) and source tarballs (`.tar.gz`) via `hatchling` and attaches them to the release.
- **Changelog Generation**: Generates automated release notes from commit history and updates the "Latest" release on GitHub.

---

## 📂 Repository Structure

```text
redloop-cybersecurity-copilot/
├── .github/workflows/         # CI/CD & Automated Release Workflows (release.yml)
├── artifacts/                 # Audit artifacts, route snapshots, test baselines & evaluation results
│   ├── eval_results.json      # Statistical benchmark outputs (SBR, FBR, Q, Macro-F1)
│   ├── final.json             # 1,094 / 1,094 test suite verification snapshot
│   ├── routes_after.json      # Complete 233-route table snapshot
│   └── ui/                    # High-resolution screenshots (Desktop/Tablet/Mobile Dark & Light)
├── data/
│   ├── knowledge/seed/        # 68+ curated security knowledge reference packs
│   └── osint/platforms.json   # 32-platform OSINT catalog & soft-404 signatures
├── docs/                      # Architecture specification & secrets audit report
├── scripts/                   # Verification tools (run_evals, validate_js_assets, gen_docs, scan_secrets)
├── src/redloop/               # Core RedLoop package
│   ├── assessment/            # Scope guard, orchestrator, terminal engine, and metrics
│   │   ├── orchestrator.py    # Multi-provider task router & copilot engine
│   │   ├── terminal_engine.py # Unified terminal engine & S1 scope enforcement
│   │   ├── scope_guard.py     # Port & DNS pinning verification gate
│   │   └── soar_engine.py     # SOAR operator authentication & playbooks
│   ├── workbench/             # Modular Security Workbench (9 domain routers)
│   │   ├── router_copilot.py  # Copilot and chat API router
│   │   ├── router_soc.py      # SOC dashboard & alert triage router
│   │   ├── router_investigations.py # Investigation pipeline router
│   │   └── shared.py          # Shared state, database dependencies & models
│   ├── audit.py               # SHA-256 hash-chained SQLite audit logger
│   ├── audit_checkpoint.py    # External HMAC checkpoint & signature verifier
│   ├── osint_engine.py        # OSINT depth, verification states & SQLite cache
│   ├── rag_engine.py          # BM25 knowledge retrieval & citation engine
│   └── scope.py               # HMAC-SHA256 scope contract manager
├── tests/                     # 1,094 automated unit, integration, and security regression tests
├── pyproject.toml             # Package metadata, dependencies, and pytest configuration
└── scope.yaml.example         # Example signed scope contract template
```

---

## 📄 License

Released under the **[MIT License](pyproject.toml)**. Intended strictly for **authorized security assessments, defensive systems hardening, research labs, and educational CTF environments**.
