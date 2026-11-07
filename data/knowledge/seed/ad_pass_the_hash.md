---
title: "Pass-the-Hash & Pass-the-Ticket Attacks & Mitigation (T1550)"
tags: ["active-directory", "pass-the-hash", "pass-the-ticket", "t1550", "laps"]
source: "MITRE ATT&CK T1550 / Microsoft Security Architecture"
---

# Pass-the-Hash & Pass-the-Ticket Attacks & Mitigation (T1550)
## Source & Authority
MITRE ATT&CK T1550 (Use Alternate Authentication Material); Microsoft Pass-the-Hash Guidance.

## Mechanics
- **Pass-the-Hash (T1550.002):** Attackers reuse captured NTLM password hashes extracted from LSASS to authenticate over SMB/RPC without needing the plaintext password.
- **Pass-the-Ticket (T1550.003):** Attackers inject stolen Kerberos TGT or TGS tickets into active logon sessions using tools like Mimikatz or Rubeus.

## Core Defenses
1. **Deploy Windows LAPS (Local Administrator Password Solution):** Generates randomized, unique local admin passwords on every host rotated automatically. Prevents lateral movement across endpoints sharing identical local admin passwords.
2. **Protected Users Security Group:** Enforce membership for privileged accounts. Disables NTLM authentication, DES/RC4 Kerberos, and credential caching in LSASS.
3. **Restricted Admin Mode for RDP:** Use `mstsc.exe /restrictedadmin` to prevent credential exposure in remote desktop sessions.
