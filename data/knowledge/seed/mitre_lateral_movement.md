---
title: "MITRE ATT&CK Lateral Movement (TA0008) Mechanisms"
tags: ["mitre", "lateral-movement", "t1021", "smb", "rdp", "winrm"]
source: "MITRE ATT&CK TA0008"
---

# MITRE ATT&CK Lateral Movement (TA0008) Mechanisms
## Source & Authority
MITRE ATT&CK Tactic TA0008 (Lateral Movement).

## Primary Vectors
- **T1021.002 (Remote Services: SMB/Windows Admin Shares):** Utilizing administrative shares (`C$`, `ADMIN$`) to deploy services remotely (PsExec, Impacket).
- **T1021.001 (Remote Desktop Protocol - RDP):** Interactive session takeover across network segments.
- **T1021.006 (Windows Remote Management - WinRM):** Executing remote PowerShell commands (`Enter-PSSession`, `Invoke-Command`) over ports 5985/5986.
