---
title: "Active Directory AS-REP Roasting Triage & Defense (T1558.004)"
tags: ["active-directory", "asrep", "t1558", "windows", "preauth"]
source: "MITRE ATT&CK T1558.004 / RFC 4120 Section 3.1"
---

# Active Directory AS-REP Roasting Triage & Defense (T1558.004)
## Source & Authority
MITRE ATT&CK T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting); RFC 4120.

## Vulnerability Mechanics
When a user account has the userAccountControl flag `DONT_REQ_PREAUTH` (Do not require Kerberos preauthentication) set, any network entity can send a standard `KRB_AS_REQ` for that username. The KDC returns a `KRB_AS_REP` containing message data encrypted with the user's password hash without verifying credentials, enabling offline dictionary cracking.

## Remediation Protocol
Audit and remove `DONT_REQ_PREAUTH` from all user accounts:
```powershell
# Identify vulnerable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Disable flag
Set-ADUser -Identity <username> -DoesNotRequirePreAuth $False
```
