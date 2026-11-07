---
title: "MITRE ATT&CK Privilege Escalation (TA0004) Techniques & Defenses"
tags: ["mitre", "privilege-escalation", "t1548", "t1055", "linux", "windows"]
source: "MITRE ATT&CK TA0004"
---

# MITRE ATT&CK Privilege Escalation (TA0004) Techniques & Defenses
## Source & Authority
MITRE ATT&CK Tactic TA0004 (Privilege Escalation).

## Primary Vectors
- **T1548.001 (SUID and SGID Binaries):** Misconfigured Linux binaries with setuid root permissions allowing command execution (e.g. `nmap`, `find`, `vim` with SUID). Audit with `find / -perm -4000 -type f 2>/dev/null`.
- **T1055 (Process Injection):** Injecting code into legitimate processes (e.g. `explorer.exe`, `svchost.exe`) via `CreateRemoteThread` or Process Hollowing to inherit elevated privileges.
- **T1068 (Exploitation for Privilege Escalation):** Exploiting OS kernel vulnerabilities (Dirty COW, Dirty Pipe).
