# REDLOOP Phase 7 Architecture: SOAR Automation & Incident Response Orchestration

**Author:** REDLOOP Architecture & Security Team  
**Date:** 2026-11-04  
**Status:** IMPLEMENTED & VERIFIED  
**Target:** Local-First Incident Response & Command Center  

---

## 1. Architectural Overview

Phase 7 introduces an integrated, local-first Security Orchestration, Automation, and Response (SOAR) layer into the REDLOOP command center. It bridges detection, intelligence, and threat hunting directly into auditable, approval-gated response workflows.

```
                           +---------------------------+
                           |   Telemetry & Ingestion   |
                           +-------------+-------------+
                                         |
                                         v
                           +---------------------------+
                           |     SOC Detection Engine  |
                           +-------------+-------------+
                                         |
                                         v
                           +---------------------------+
                           |  Event Trigger Engine     |
                           |  (Deduplication & Queue)  |
                           +-------------+-------------+
                                         |
                                         v
     +-----------------------------------+-----------------------------------+
     |                                   |                                   |
     v                                   v                                   v
[Auto Investigation]             [Defensive Actions]             [Approval-Gated Actions]
- Retrieve Related Events        - Local Blocklist Simulation    - Endpoint Isolation
- Enrich Indicators (IP/Hash)    - Recommendation Logging        - Account Lockout
- Run Bounded Threat Hunt        - Analyst Notification          (Requires Cryptographic
                                                                  Capability Token)
                                         |
                                         v
                           +---------------------------+
                           |  Incident Case Management |
                           |  - Notes & Timeline       |
                           |  - Evidence Ledger Links  |
                           |  - State Lifecycle        |
                           +---------------------------+
```

---

## 2. Core Components

### 2.1 SOAR Workflow Engine (`soar_engine.py`)
- Declarative workflow definitions with semantic versions, required telemetry inputs, and closure criteria.
- 11-State Formal State Machine:
  `DRAFT`, `VALIDATED`, `READY`, `RUNNING`, `WAITING_FOR_APPROVAL`, `PAUSED`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`, `BLOCKED`.
- State transitions are strictly validated against a directed acyclic transition matrix (`VALID_TRANSITIONS`).
- Persistent SQLite storage (`data/soar.db`) tracking execution history, executed steps, step outputs, and audit logs across process restarts.

### 2.2 Trigger & Deduplication Engine
- Supports triggers originating from:
  - `ALERT`: SOC detection alert matches
  - `INCIDENT`: Correlated multi-stage incidents
  - `HUNT`: Threat-hunting findings
  - `SIGMA`: Sigma v2 rule matches
  - `INTEL`: Threat intelligence indicator updates
  - `MANUAL`: Direct analyst dispatch
- Computes SHA-256 deduplication keys over `(trigger_type, source_record_id, target_context)` to prevent duplicate automated executions unless explicit re-run is authorized.

### 2.3 Action Registry (`soar_actions.py`)
- Strictly typed action registry with sandbox isolation. No dynamic `eval()` or arbitrary shell code.
- Segregated into three operational categories:
  1. **INVESTIGATION (Read-Only)**: Automatically executed (e.g. `retrieve_related_events`, `enrich_indicator`, `run_bounded_hunt`).
  2. **DEFENSIVE (Simulated)**: Safe, simulated boundary actions (e.g. `simulate_indicator_blocklist`, `create_containment_recommendation`). Always labeled `SIMULATED`.
  3. **CONTAINMENT (Approval-Gated)**: High-risk actions (e.g. `isolate_endpoint`, `disable_account`) strictly requiring single-use capability tokens. Returns `NOT_CONFIGURED` if enterprise provider credentials are absent.

### 2.4 Case Management Engine (`case_management.py`)
- Persistent SQLite-backed incident tracking (`data/cases.db`).
- Full investigation lifecycle:
  `OPEN` -> `INVESTIGATING` -> `PENDING_APPROVAL` -> `CONTAINMENT_IN_PROGRESS` -> `MONITORING` -> `RESOLVED` -> `CLOSED` -> `REOPENED`.
- Links alerts, incidents, and immutable evidence ledger records without mutating underlying telemetry.
- Preserves analyst notes, chronological timeline audit trails, and reopen history.

### 2.5 Security Boundaries & SSRF Protection
- Outbound notifications enforce destination IP validation via `SafeWebhookClient`.
- Prohibits RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`, `localhost`), link-local (`169.254.169.254`), and non-HTTPS endpoints.
