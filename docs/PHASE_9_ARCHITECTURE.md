# REDLOOP Phase 9 — Autonomous SOC Operations & Detection Engineering Architecture

## 1. Executive Summary

REDLOOP Phase 9 delivers an enterprise-grade Autonomous SOC Operations & Detection Engineering subsystem. It transitions REDLOOP from reactive, tool-by-tool investigation to continuous, cross-platform telemetry ingestion, transparent multi-entity event correlation, indicator lifecycle tracking, and copilot-assisted operational response.

The implementation strictly maintains REDLOOP's local-first architecture: when external enterprise providers are unconfigured or offline, all detection rules, correlation heuristics, IOC workflows, and operational Copilot queries execute locally against sqlite-backed datastores without external dependencies.

---

## 2. Core Architectural Subsystems

```
                                +--------------------------------------------+
                                |      Enterprise Security Integrations      |
                                | (Defender, CrowdStrike, Splunk, Wazuh, etc)|
                                +---------------------+----------------------+
                                                      |
                                                      v
                                +--------------------------------------------+
                                |        TelemetrySyncPipeline (B1)          |
                                |  - Provider Checkpoints & Cursors          |
                                |  - Event Deduplication (Unique Keys)       |
                                |  - Provenance Tracking & Job State Machine |
                                +---------------------+----------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +--------------------------------+                       +---------------------------------+
         | DetectionEngineeringManager(B2)|                       | IncidentCorrelationEngine (B3)  |
         | - Unified Rule Inventory       |                       | - Multi-Entity Graph Matching   |
         | - MITRE ATT&CK Matrix Coverage |                       | - Mathematical Scoring Formula  |
         | - Positive/Negative Test Cases |                       | - Confirmed vs Inferred Links   |
         | - False-Positive Feedback Loop |                       | - Merge & Split Audit Trail     |
         +--------------------------------+                       +---------------------------------+
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                +--------------------------------------------+
                                |       IOC Lifecycle Management (B5)        |
                                | - Typed Indicators (IP, Domain, Hash, etc) |
                                | - State Machine & Analyst Disposition Log  |
                                | - Non-Fabrication Reputation Safeguards    |
                                +---------------------+----------------------+
                                                      |
                                                      v
                                +--------------------------------------------+
                                |      SOCCopilot Operational Engine (B8)    |
                                | - Structured Intent Dispatch               |
                                | - Evidence Citations & Attack Progression  |
                                | - Cryptographic Approval for Containment   |
                                +--------------------------------------------+
```

---

## 3. Subsystem Breakdown

### 3.1 Unified Telemetry Synchronization Pipeline (`soc_sync.py`)
- **Cursor & Checkpoint Tracking**: Tracks `last_sync_time`, `last_cursor_id`, and `total_events_ingested` per provider in SQLite.
- **Typed Sync Jobs**: States: `PENDING`, `RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`.
- **Deduplication**: Enforces `UNIQUE(provider_id, original_event_id)` at database level. Duplicate events are safely discarded without error.
- **Operator Cancellation**: Active synchronization passes can be interrupted mid-stream via `/api/soc/sync/{job_id}/cancel`.
- **Provenance Preservation**: Preserves original source IDs, raw logs, ingestion timestamps, and normalization references.

### 3.2 Cross-Platform Detection Engineering Layer (`detection_engineering.py`)
- **Unified Rule Format**: Defines detection rules with ID (`RL-DET-XXX`), tactic, technique ID, severity, confidence, query logic, and positive/negative test fixtures.
- **Built-in Rules**:
  - `RL-DET-001`: Obfuscated PowerShell Download & Execution (`T1059.001`, Execution)
  - `RL-DET-002`: Pass-the-Hash / Overpass-the-Hash Authentication (`T1550.002`, Lateral Movement)
  - `RL-DET-003`: LSASS Memory Dumping via Procdump / Comsvcs (`T1003.001`, Credential Access)
  - `RL-DET-004`: Suspicious Scheduled Task Persistence (`T1053.005`, Persistence)
- **Automated Rule Validation**: Enforces technique validation against MITRE ATT&CK enterprise catalog, severity bounds, and rule structure.
- **Test Harness**: Runs built-in positive and negative test cases against every rule on demand.
- **ATT&CK Coverage Matrix**: Computes coverage percentage across 14 enterprise tactics, identifying active techniques and coverage gaps.
- **False-Positive Tracking**: Records analyst feedback, adjustment reasons, and hit statistics per rule.

### 3.3 Multi-Entity Incident Correlation Engine (`incident_correlation.py`)
- **Transparent Mathematical Correlation Formula**:
  $$\text{Score} = \min(1.0, S_{\text{entity}} + S_{\text{temporal}} + S_{\text{technique}})$$
  - **Entity Overlap** ($S_{\text{entity}} \le 0.50$):
    - Host match: $+0.25$
    - User match: $+0.25$
    - IP match: $+0.20$
  - **Temporal Proximity** ($S_{\text{temporal}} \le 0.15$):
    - Within 15 minutes: $+0.15$
    - Within 1 hour: $+0.10$
    - Within 24 hours: $+0.05$
  - **Technique Progression** ($S_{\text{technique}} \le 0.20$):
    - Multi-stage attack killchain progression: $+0.20$
- **Confirmed Observations vs. Inferred Relationships**:
  - Direct matches (e.g., matching host, user, or IP) are classified as `CONFIRMED_OBSERVATION`.
  - Proximity or heuristic associations are classified as `INFERRED_RELATIONSHIP`.
- **Incident Merge & Split Operations**:
  - Supports merging related incidents into a single master incident with full history.
  - Supports splitting mistakenly correlated events into a new incident with full audit trails.

### 3.4 Threat Intelligence & IOC Lifecycle Engine (`ioc_engine.py`)
- **Typed Indicators**: Supports `IP`, `DOMAIN`, `URL`, `HASH`, `EMAIL`.
- **Explicit Lifecycle States**:
  - `NEW`: Newly observed indicator.
  - `UNDER_REVIEW`: Actively investigated by analyst.
  - `CONFIRMED_MALICIOUS`: Verified threat node.
  - `BENIGN`: Verified legitimate resource.
  - `FALSE_POSITIVE`: Initially flagged indicator cleared by evidence.
- **Non-Fabrication Policy**: Missing or unconfigured provider data defaults strictly to `UNKNOWN`, never synthesized as benign or safe.
- **Analyst Disposition Audit Trail**: Every status transition logs the analyst identity, timestamp, and justification reason.

### 3.5 Consolidated SOC Operational Metrics (`soc_metrics.py`)
- Calculates:
  - **MTTD (Mean Time to Detect)**: Average delta between event timestamp and incident creation.
  - **MTTR (Mean Time to Respond)**: Average delta between incident detection and containment/resolution.
  - **Telemetry Sync Rate**: Percentage of successfully ingested events over total synchronization attempts.
  - **Provider Availability**: Percentage of operational configured providers.
  - **Alert Reduction Rate**: Compression ratio achieved by multi-entity correlation relative to raw ingested events.

### 3.6 Copilot Operational Intelligence (`soc_copilot.py`)
- Extends `SOCCopilotEngine` with `handle_operational_query()` for 6 structured operational intents:
  1. `investigate_incident`: Summarizes incident scope, affected entities, ATT&CK techniques, and evidence citations.
  2. `show_evidence`: Returns chronologically ordered forensic evidence for an incident.
  3. `find_related`: Surfaces cross-incident entity linkages and historical patterns.
  4. `explain_attack`: Provides human-readable narrative explaining the adversary progression across kill chain stages.
  5. `prepare_containment`: Drafts an actionable containment plan requiring cryptographic approval capability tokens.
  6. `verify_isolation`: Checks live EDR status; strictly reports failure/unverified when external EDR is offline.

---

## 4. REST API Endpoints Registered in Workbench

| Route | Method | Description |
|---|---|---|
| `/api/soc/sync/jobs` | GET | List telemetry synchronization jobs with pagination and status filters |
| `/api/soc/sync/trigger` | POST | Trigger an immediate telemetry synchronization pass for a provider |
| `/api/soc/sync/{job_id}/cancel` | POST | Cancel an active telemetry synchronization pass |
| `/api/soc/sync/metrics` | GET | Retrieve synchronization throughput, success rates, and lag metrics |
| `/api/detections/rules` | GET | List detection rules with optional technique and status filters |
| `/api/detections/rules/{id}/test` | POST | Execute automated positive/negative test harness on a detection rule |
| `/api/detections/coverage` | GET | Get MITRE ATT&CK enterprise coverage matrix and gap analysis |
| `/api/detections/rules/{id}/false-positive` | POST | Submit analyst false-positive feedback and adjustment reason |
| `/api/incidents` | GET | List correlated incidents with severity and merge status filters |
| `/api/incidents/{id}` | GET | Retrieve detailed incident dossier with linked events and evidence |
| `/api/incidents/correlate` | POST | Ingest and correlate a security event into the incident graph |
| `/api/incidents/merge` | POST | Merge two correlated incidents with audit tracking |
| `/api/incidents/{id}/split` | POST | Split selected events out of an incident into a new incident |
| `/api/iocs` | GET | List threat intelligence indicators with type and state filters |
| `/api/iocs` | POST | Register a new threat indicator |
| `/api/iocs/{id}/disposition` | POST | Update IOC lifecycle state and record analyst disposition audit |
| `/api/metrics/soc` | GET | Retrieve consolidated SOC operational metrics (MTTD, MTTR, etc.) |
| `/api/soc/copilot/op` | POST | Submit operational queries to the SOC Copilot engine |

---

## 5. UI Workspace Tab: Autonomous SOC Operations

Integrated seamlessly into the single-page application at `view-soc-ops` (accessible via the `Autonomous SOC` navigation tab):
- **Operational Metrics Bar**: Visual cards displaying MTTD, MTTR, Telemetry Sync Rate, Provider Availability, and Alert Reduction Rate.
- **Correlated Incidents Workspace**: Live incident table with severity badges, affected entities, confidence scores, and action buttons for investigation, containment preparation, and merge/split.
- **Telemetry Sync Control Center**: Sync triggering form with provider selector, limit slider, and active synchronization job status stream.
- **Threat Intelligence & IOCs**: Lifecycle management table with state badges (`CONFIRMED_MALICIOUS`, `BENIGN`, `UNDER_REVIEW`, etc.) and disposition action modal.
- **Detection Engineering & ATT&CK Coverage**: Rule repository table with test harness triggers, hit tracking, false-positive reporting, and visual ATT&CK technique coverage indicators.
