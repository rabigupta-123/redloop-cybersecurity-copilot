# Splunk Enterprise & Cloud SIEM Integration Setup

## Overview

The REDLOOP Splunk Adapter integrates with Splunk REST API (port 8089) for server health, oneshot search execution, and alert extraction.

---

## 1. Capabilities Supported

- `READ_ALERTS`: Ingests firing alerts and notable events.
- `SEARCH_EVENTS`: Executes bounded SPL queries via oneshot search jobs.

---

## 2. Configuration & Authentication

Supports Splunk session tokens (`Authorization: Splunk <token>`) or Basic authentication (`Authorization: Basic <base64>`).

### Environment Variables
```bash
export SPLUNK_HOST="splunk.corp.internal"
export SPLUNK_PORT="8089"
export SPLUNK_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
# Alternative:
# export SPLUNK_USER="admin"
# export SPLUNK_PASSWORD="YourSplunkPassword"
```

---

## 3. Read-Only SPL Guardrails

To prevent data corruption, modification, or lateral exfiltration, all queries pass through `PROHIBITED_SPL_COMMANDS` validation. The following commands immediately trigger a `ValueError`:
- `delete`
- `outputlookup`
- `outputcsv`
- `collect`
- `sendemail`
- `run`
- `script`

All queries automatically append `| head {limit}` (maximum ceiling of 100) if not explicitly present.
