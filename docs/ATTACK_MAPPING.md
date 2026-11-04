# REDLOOP MITRE ATT&CK Mapping & Coverage Specification

**Framework Version:** MITRE Enterprise ATT&CK v15  
**Engine:** `src/redloop/assessment/attack_mapping.py`  
**API Endpoints:** `/api/hunting/attack/tactics`, `/api/hunting/attack/techniques`, `/api/hunting/attack/matrix`

---

## 1. Enterprise Tactics Catalog (14 Tactics)

REDLOOP maps telemetry and incident progression across all 14 official Enterprise tactics:

1. **TA0043 — Reconnaissance:** Adversary actively or passively gathering target intelligence.
2. **TA0042 — Resource Development:** Establishing infrastructure, accounts, and tools.
3. **TA0001 — Initial Access:** Techniques used to gain an initial foothold (e.g. T1190 Exploit Public-Facing App, T1566 Phishing).
4. **TA0002 — Execution:** Adversary-controlled code running on local or remote systems (e.g. T1059.001 PowerShell).
5. **TA0003 — Persistence:** Maintaining access across restarts or credential changes (e.g. T1505.003 Web Shell).
6. **TA0004 — Privilege Escalation:** Gaining elevated system permissions (e.g. T1548.003 Sudo and Sudo Caching).
7. **TA0005 — Defense Evasion:** Avoiding detection by security controls (e.g. T1027 Obfuscated Files).
8. **TA0006 — Credential Access:** Stealing account names and credentials (e.g. T1110.001 Password Guessing).
9. **TA0007 — Discovery:** Gaining situational awareness of system and network architecture (e.g. T1046 Network Service Discovery).
10. **TA0008 — Lateral Movement:** Extending access to other systems on the network (e.g. T1021.002 SMB Admin Shares).
11. **TA0009 — Collection:** Assembling targeted data for exfiltration (e.g. T1005 Data from Local System).
12. **TA0011 — Command and Control:** Establishing communication channels with controlled systems (e.g. T1071.004 DNS C2).
13. **TA0010 — Exfiltration:** Stealing sensitive data from the enterprise network (e.g. T1041 Exfiltration Over C2).
14. **TA0040 — Impact:** Disrupting, manipulating, or destroying system availability and integrity (e.g. T1486 Ransomware).

---

## 2. Detection Rule to Technique Mapping

| Rule ID | Rule Title | Mapped Technique | Primary Tactic | Default Confidence |
|:---|:---|:---|:---:|:---:|
| `SEC-AUTH-001` | Brute-Force Authentication Activity | `T1110.001` (Password Guessing) | `TA0006` | 0.90 |
| `SEC-AUTH-002` | Successful Logon Following Failures | `T1078` (Valid Accounts) | `TA0001` | 0.88 |
| `SEC-PROC-001` | Obfuscated PowerShell Execution | `T1059.001` (PowerShell) | `TA0002` | 0.95 |
| `SEC-PROC-002` | Web Server Spawning Interactive Shell | `T1505.003` (Web Shell) | `TA0003` | 0.95 |
| `SEC-WEB-001` | Web Exploitation Indicators (SQLi/Path) | `T1190` (Exploit Public-Facing App) | `TA0001` | 0.92 |
| `SEC-NET-001` | DNS Tunneling & Covert Channel | `T1071.004` (DNS Communication) | `TA0011` | 0.85 |
| `SEC-HASH-001` | Known Malicious File Hash Match | `T1059` / `T1505.003` | `TA0002` | 0.85 |

---

## 3. Matrix Heatmap Generation & Export

The matrix endpoint computes tactic-level coverage:

$$\text{Coverage Percentage} = \frac{\text{Covered Tactics}}{14} \times 100\%$$

Each covered tactic lists the number of unique techniques mapped, maximum confidence observed, and associated evidence provenance references. Reports can be exported as raw JSON or as formatted executive Markdown tables via `GET /api/hunting/attack/matrix?format=markdown`.
