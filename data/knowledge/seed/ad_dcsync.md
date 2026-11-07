---
title: "Active Directory DCSync Attack & Permissions Audit (T1003.006)"
tags: ["active-directory", "dcsync", "t1003", "drsuapi", "mimikatz"]
source: "MITRE ATT&CK T1003.006 / Microsoft MS-DRSR Protocol Specification"
---

# Active Directory DCSync Attack & Permissions Audit (T1003.006)
## Source & Authority
MITRE ATT&CK T1003.006 (OS Credential Dumping: DCSync); Microsoft MS-DRSR (Directory Replication Service Remote Protocol).

## Attack Mechanics
DCSync simulates the behavior of a Domain Controller using the Directory Replication Service Remote Protocol (`MS-DRSR` / `drsuapi`). An account possessing `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights requests password hashes (including `KRBTGT` and Enterprise Admins) directly from a domain controller without running code on the DC itself.

## Detection Signatures (EventID 4662)
Monitor EventID `4662` (An operation was performed on an object) where the accessed property matches replication GUIDs:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
Filter out authorized domain controllers (`NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS`). Any invocation by a standard user or service account is a high-confidence alert.
