# REDLOOP SOAR Action Support Matrix

**Module:** `src/redloop/assessment/soar_actions.py`  

---

## 1. Action Registry & Capabilities

| Action Name | Category | Automation Tier | Requires Approval | Supported Environments |
|:---|:---:|:---:|:---:|:---|
| `retrieve_related_events` | INVESTIGATION | Automated | **NO** | Local SQLite / In-Memory Event Ledger |
| `enrich_indicator` | INVESTIGATION | Automated | **NO** | Local Threat Intel Engine / RFC1918 Parser |
| `run_bounded_hunt` | INVESTIGATION | Automated | **NO** | Local Threat Hunting Engine |
| `simulate_indicator_blocklist` | DEFENSIVE | Automated | **NO** | Local In-Memory / Simulation Table (SIMULATED) |
| `create_containment_recommendation` | DEFENSIVE | Automated | **NO** | Case Management Timeline |
| `isolate_endpoint` | CONTAINMENT | Approval-Gated | **YES** | Local Simulation (`SIMULATED`), External Provider (`NOT_CONFIGURED` without keys) |
| `disable_account` | CONTAINMENT | Approval-Gated | **YES** | Local Simulation (`SIMULATED`), External IdP (`NOT_CONFIGURED` without keys) |
| `send_webhook_notification` | NOTIFICATION | Automated | **NO** | Validated Public HTTPS Webhooks (SSRF Protected) |

---

## 2. Real vs Simulated Execution Principles

1. **No Destructive Action May Execute Automatically**: Actions in `CONTAINMENT` strictly halt execution until an operator capability token is presented.
2. **Simulation Transparency**: Local simulation actions are always recorded with `is_simulated = True` and status `SIMULATED`.
3. **Unconfigured Integrations**: In the absence of confirmed external provider API credentials (e.g. CrowdStrike Falcon, SentinelOne, Okta, Active Directory), requests return `NOT_CONFIGURED`. REDLOOP never fabricates confirmed third-party cloud execution.
4. **SSRF Guard**: Webhook destinations targeting `localhost`, `127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` are blocked before any network transmission occurs.
