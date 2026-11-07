---
title: "NTLM Flaws, Relay Attacks & Modern Mitigation"
tags: ["auth", "ntlm", "active-directory", "relay", "mitm", "smb"]
source: "Microsoft MS-NLMP / MITRE ATT&CK T1557.001"
---

# NTLM Flaws, Relay Attacks & Modern Mitigation
## Source & Authority
Microsoft MS-NLMP (NT LAN Manager Authentication Protocol); MITRE ATT&CK T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay).

## Vulnerability Mechanics
NTLM is a legacy challenge-response protocol lacking mutual authentication and cryptographic binding to the transport channel.
- **Relay Attack Flow:** An attacker coerces or intercepts NTLM authentication (via LLMNR/mDNS spoofing or PetitPotam) and forwards (relays) the victim's authentication challenge-response directly to an unhardened service (SMB, LDAP, HTTP AD CS) without cracking the password hash.

## Defensive Hardening
1. **Enforce SMB and LDAP Signing:** Require SMB Signing (`RequireSecuritySignature = 1`) and LDAP Channel Binding (`LdapEnforceChannelBinding = 2`).
2. **Extended Protection for Authentication (EPA):** Enable EPA on IIS and AD CS web endpoints to bind TLS channel bindings to the NTLM token.
3. **Disable NTLM:** Transition to Kerberos; restrict NTLM usage via Group Policy (`Network security: Restrict NTLM: Outgoing traffic to remote servers = Deny all`).
