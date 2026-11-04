# REDLOOP Incident Response Playbook Catalog (10 Built-In Playbooks)

**Version:** 1.0.0  
**Engine:** `src/redloop/assessment/soar_engine.py`  

---

## 1. Catalog Summary

| Playbook ID | Category | Title | Containment Gate | Automation Tier |
|:---|:---|:---|:---:|:---:|
| `WF-BRUTE-FORCE` | Identity | Brute-Force Authentication Investigation & Edge Blocking | Simulated | Automated |
| `WF-CRED-COMPROMISE` | Identity | Suspected Credential Compromise & Account Lockout | **Required** | Approval-Gated |
| `WF-POWERSHELL-EXEC` | Endpoint | Suspicious PowerShell Execution & Host Isolation | **Required** | Approval-Gated |
| `WF-WEB-ATTACK` | Web App | Web Application Attack & Web Shell Neutralization | Simulated | Automated |
| `WF-PHISHING` | Email | Phishing Investigation & Domain Takedown Triage | Recommended | Automated |
| `WF-MALWARE-HASH` | Endpoint | Malware Indicator Triage & Endpoint Quarantine | **Required** | Approval-Gated |
| `WF-OUTBOUND-C2` | Network | Suspicious Outbound Communication & Null-Routing | Simulated | Automated |
| `WF-DATA-EXFIL` | Data Protection | Potential Data Exfiltration & Channel Severance | Recommended | Automated |
| `WF-DNS-TUNNEL` | Network | DNS Tunneling Investigation & Resolver Filtering | Simulated | Automated |
| `WF-VULN-EXPLOIT` | Vulnerability | Vulnerability Exploitation Alert & Virtual Patching | Recommended | Automated |

---

## 2. Playbook Specifications

### 2.1 WF-BRUTE-FORCE
- **Triggers:** `SEC-AUTH-001`, `alert.failed_logins`
- **Telemetry:** Auth log failure counts, source IP, username
- **Investigation Steps:** `retrieve_related_events`, `enrich_indicator` (IP reputation)
- **Defensive Action:** `simulate_indicator_blocklist` (local simulated edge block)
- **Closure Criteria:** Attacking source IP blacklisted and targeted account passwords rotated.

### 2.2 WF-CRED-COMPROMISE
- **Triggers:** `SEC-AUTH-002`, `alert.anomalous_login`
- **Telemetry:** Successful auth following failures, geographic anomaly
- **Investigation Steps:** `retrieve_related_events` (session verification)
- **Approval Gate:** Step 2 halts at `WAITING_FOR_APPROVAL` for `disable_account`
- **Closure Criteria:** Active session tokens revoked and credentials rotated out-of-band.

### 2.3 WF-POWERSHELL-EXEC
- **Triggers:** `SEC-PROC-001`, `sigma.process_creation.powershell`
- **Telemetry:** Sysmon Event ID 1, command-line arguments, parent process
- **Investigation Steps:** Process tree lineage inspection via `retrieve_related_events`
- **Approval Gate:** Step 2 halts at `WAITING_FOR_APPROVAL` for `isolate_endpoint`
- **Closure Criteria:** Obfuscated process terminated and endpoint isolated.

### 2.4 WF-WEB-ATTACK
- **Triggers:** `SEC-WEB-001`, `sigma.webserver.sqli_traversal`
- **Telemetry:** Web server access logs, URI parameters, HTTP response codes
- **Investigation Steps:** HTTP response analysis via `retrieve_related_events`
- **Defensive Action:** `simulate_indicator_blocklist` (simulated WAF pattern injection)
- **Closure Criteria:** Vulnerable code path patched and client IP blocked.

### 2.5 WF-PHISHING
- **Triggers:** `alert.phishing_email`, `hunt.suspicious_domain`
- **Telemetry:** Sender headers, link domains, attachment hashes
- **Investigation Steps:** `enrich_indicator` (domain reputation and registrar history)
- **Defensive Action:** `create_containment_recommendation` (mail gateway purge)
- **Closure Criteria:** Messages purged from mailboxes and domain blocked.

### 2.6 WF-MALWARE-HASH
- **Triggers:** `SEC-HASH-001`, `alert.av_detection`
- **Telemetry:** SHA-256 hash, file system location, AV signature
- **Investigation Steps:** `enrich_indicator` (known hash cross-correlation)
- **Approval Gate:** Step 2 halts at `WAITING_FOR_APPROVAL` for `isolate_endpoint`
- **Closure Criteria:** Malicious payload quarantined and host isolated.

### 2.7 WF-OUTBOUND-C2
- **Triggers:** `SEC-NET-001`, `sigma.network_connection.beaconing`
- **Telemetry:** Netflow connection duration, destination IP, byte counts
- **Investigation Steps:** `enrich_indicator` (destination IP C2 reputation)
- **Defensive Action:** `simulate_indicator_blocklist` (blackhole route simulation)
- **Closure Criteria:** Outbound socket killed and C2 IP null-routed.

### 2.8 WF-DATA-EXFIL
- **Triggers:** `alert.high_egress_volume`
- **Telemetry:** Netflow byte counters, destination cloud IP
- **Investigation Steps:** `retrieve_related_events` (data volume check)
- **Defensive Action:** `create_containment_recommendation` (channel severance)
- **Closure Criteria:** File transfer stopped and egress credentials rotated.

### 2.9 WF-DNS-TUNNEL
- **Triggers:** `alert.dns_entropy`, `sigma.dns.tunneling`
- **Telemetry:** Suricata DNS queries, subdomain entropy
- **Investigation Steps:** `retrieve_related_events` (query frequency analysis)
- **Defensive Action:** `simulate_indicator_blocklist` (resolver sinkhole simulation)
- **Closure Criteria:** Query resolution sinkholed at internal resolver.

### 2.10 WF-VULN-EXPLOIT
- **Triggers:** `alert.cve_exploit_attempt`
- **Telemetry:** CVE ID, URI query, web application error code
- **Investigation Steps:** `retrieve_related_events` (exploit payload review)
- **Defensive Action:** `create_containment_recommendation` (virtual patch deployment)
- **Closure Criteria:** Reverse proxy virtual patch verified and vendor update applied.
