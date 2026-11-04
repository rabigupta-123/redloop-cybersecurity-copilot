# Wazuh SIEM & XDR Manager Integration Setup

## Overview

The REDLOOP Wazuh Adapter connects the REDLOOP platform to Wazuh Manager REST APIs (v4.x). It enables real-time alert ingestion, agent status verification, and security telemetry normalization into REDLOOP's Universal Security Event format.

---

## 1. Capabilities Supported

- `READ_ALERTS`: Pulls detection alerts from `/alerts` endpoint.
- `SEARCH_EVENTS`: Queries alerts and events across all agents.
- `GET_AGENT_HEALTH`: Queries agent inventory and operational states from `/agents`.

---

## 2. Configuration & Authentication

Wazuh uses HTTP Basic authentication against `/security/user/authenticate` to retrieve a short-lived JSON Web Token (JWT) with 15-minute TTL. REDLOOP caches this token automatically and refreshes it upon expiration.

### Environment Variables
```bash
export WAZUH_URL="https://wazuh.corp.internal:55000"
export WAZUH_USER="wazuh-wui"
export WAZUH_PASSWORD="YourStrongWazuhPassword"
export WAZUH_VERIFY_SSL="true"
```

---

## 3. Data Normalization Reference

Wazuh alert documents are normalized to `UniversalSecurityEvent`:
- Rule level 12-15 -> `EventSeverity.CRITICAL`
- Rule level 8-11  -> `EventSeverity.HIGH`
- Rule level 4-7   -> `EventSeverity.MEDIUM`
- Rule level 0-3   -> `EventSeverity.LOW`
- Rule groups (`pam`, `sshd`, `authentication_failed`) -> `EventCategory.AUTHENTICATION`
- Rule groups (`process`, `sysmon`) -> `EventCategory.PROCESS`

---

## 4. Offline / Air-Gapped Simulation Mode

When unconfigured, the adapter returns `status: "NOT_CONFIGURED"`, allowing REDLOOP to run completely offline without crashing or raising unhandled connection exceptions.
