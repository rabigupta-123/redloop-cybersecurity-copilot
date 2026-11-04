# REDLOOP Threat Hunting Operator's Guide

This guide describes how to conduct structured, hypothesis-driven threat hunting investigations in REDLOOP.

---

## 1. Natural Language Hunting Queries

The Threat Hunting engine accepts plain English queries and translates them into structured filter ASTs.

### Example Queries

```text
Hunt for PowerShell executions targeting 198.51.100.45 in the last 24 hours
```
- **Extracted Entity:** `source_ip == '198.51.100.45'`, `process_name contains 'powershell'`
- **Target Sources:** `windows_sysmon`
- **Time Window:** Last 24 hours

```text
Find sudo executions on linux Bastion in the past hour
```
- **Extracted Entity:** `command_line contains 'sudo'`
- **Target Sources:** `linux_auth`
- **Time Window:** Last 1 hour

```text
Search for CVE-2021-44228 exploitation attempts
```
- **Extracted Entity:** `cve_id == 'CVE-2021-44228'`
- **Target Sources:** `web_access`, `suricata_eve`

---

## 2. Query Plan Preview & Safety Checks

Before executing expensive queries across millions of telemetry events, request a pre-execution query plan:

```http
POST /api/hunting/query/plan
Content-Type: application/json

{
  "query": "Hunt for powershell commands from 192.168.1.150",
  "limit": 50
}
```

### Plan Response
```json
{
  "success": true,
  "plan": {
    "query_id": "hunt-3f41a82d",
    "natural_language": "Hunt for powershell commands from 192.168.1.150",
    "target_sources": ["windows_sysmon"],
    "projected_scope": "Telemetry sources: windows_sysmon",
    "estimated_cost": "LOW",
    "limit": 50,
    "safety_checks_passed": true,
    "explanation": "Query targets 1 source categories over a complete window with 2 parameterized filter clauses."
  }
}
```

---

## 3. Executing a Hunt & Hypothesis Tracking

```http
POST /api/hunting/query/execute
Content-Type: application/json

{
  "query": "Hunt for SQL injection from 198.51.100.99",
  "hypothesis": "External actor attempting SQL injection to exfiltrate database records"
}
```

### Result Schema
- `hypothesis_status`: `CONFIRMED` (if matching events found), `REFUTED` (if sufficient telemetry exists with 0 matches), `INCONCLUSIVE` (insufficient data).
- `matched_entities`: Extracted IPs, hostnames, users, and processes.
- `evidence_provenance`: List of raw SHA-256 evidence IDs backing the findings.
- `suggested_followups`: Automated next investigation steps recommended by the engine.

---

## 4. Reconstructing Attack Chains

Once related events are uncovered, trigger an attack chain reconstruction:

```http
POST /api/hunting/chain/reconstruct
Content-Type: application/json

{
  "title": "Suspected Gateway Compromise"
}
```

The response returns:
1. Ordered kill-chain progression across 13 stages.
2. Steps tagged as `OBSERVED` (direct evidence) vs `INFERRED` (heuristic linkage).
3. Telemetry gaps flagged explicitly where intermediate actions were not logged.
4. Total calculated adversary dwell time.
