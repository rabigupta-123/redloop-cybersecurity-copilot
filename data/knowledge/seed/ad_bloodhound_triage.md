---
title: "Active Directory Graph Analysis & Attack Path Management (BloodHound)"
tags: ["active-directory", "bloodhound", "attack-paths", "acl-abuse", "t1069"]
source: "MITRE ATT&CK T1069.002 / BloodHound Documentation"
---

# Active Directory Graph Analysis & Attack Path Management (BloodHound)
## Source & Authority
MITRE ATT&CK T1069.002 (Permission Groups Discovery: Domain Groups); BloodHound Project Documentation.

## Attack Path Analysis
Attackers analyze Active Directory object relationships to identify shortest paths to `Domain Admins`:
- **GenericAll / GenericWrite:** Complete control over target object. Allows resetting passwords, altering group memberships, or setting SPNs.
- **WriteDacl:** Allows an attacker to grant themselves full control (`GenericAll`) over the target object.
- **ForceChangePassword:** Allows resetting target account's password without knowing the current password.

## Defensive Hardening
1. Regularly ingest AD telemetry using SharpHound / BloodHound CE to audit excessive delegated rights.
2. Tiered Administrative Architecture (Tier 0 Domain Controllers, Tier 1 Servers, Tier 2 Workstations). Privileged Tier 0 credentials must never log on to Tier 1 or 2 assets.
