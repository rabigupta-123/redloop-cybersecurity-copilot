---
title: "MITRE ATT&CK Execution (TA0002) & Living-off-the-Land Binaries"
tags: ["mitre", "execution", "t1059", "powershell", "wmi", "lolbins"]
source: "MITRE ATT&CK TA0002 / LOLBAS Project"
---

# MITRE ATT&CK Execution (TA0002) & Living-off-the-Land Binaries
## Source & Authority
MITRE ATT&CK Tactic TA0002 (Execution); LOLBAS (Living Off The Land Binaries and Scripts).

## Primary Techniques
- **T1059.001 (PowerShell):** Execution of scripts or encoded commands (`powershell.exe -enc ...`). Enforce PowerShell Constrained Language Mode (CLM) and Script Block Logging (Event ID 4104).
- **T1047 (Windows Management Instrumentation - WMI):** Utilizing `wmic` or PowerShell WMI cmdlets to spawn processes locally or remotely.
- **T1053 (Scheduled Task/Job):** Scheduling persistence or deferred execution (`schtasks /create`).
