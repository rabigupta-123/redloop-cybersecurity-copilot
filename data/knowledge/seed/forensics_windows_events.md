---
title: "Windows Security Event Log Forensics & Core Event IDs"
tags: ["forensics", "windows", "event-log", "incident-response", "evtx"]
source: "Microsoft Windows Security Auditing / NIST SP 800-86"
---

# Windows Security Event Log Forensics & Core Event IDs
## Source & Authority
Microsoft Windows Security Auditing Documentation; NIST SP 800-86 (Guide to Integrating Forensic Techniques).

## Critical Event IDs & Interpretation
| Event ID | Description | Forensic Significance |
| :--- | :--- | :--- |
| **4624** | Successful Logon | Identify logon types: Type 2 (Interactive), Type 3 (Network/SMB), Type 10 (Remote Desktop/RDP). |
| **4625** | Failed Logon | High volumes indicate password guessing, credential stuffing, or brute force (MITRE T1110). |
| **4688** | New Process Created | Requires command-line auditing. Inspect CLI switches, execution paths, and parent processes. |
| **7045** | Service Created | New service installation indicates persistence or lateral movement (e.g. PsExec). |
| **4720** | User Account Created | Rogue local or domain account creation for persistence. |
| **4768 / 4769**| Kerberos TGT / TGS Request | Telemetry for AS-REP roasting (4768) and Kerberoasting (4769). |
| **1102** | Audit Log Cleared | Anti-forensic activity. High-severity immediate alert. |
