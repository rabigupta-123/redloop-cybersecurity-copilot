---
title: "Active Directory Kerberoasting Attack & Defense (T1558.003)"
tags: ["active-directory", "kerberoast", "t1558", "windows", "defense"]
source: "MITRE ATT&CK T1558.003 / Microsoft MS-KILE"
---

# Active Directory Kerberoasting Attack & Defense (T1558.003)
## Source & Authority
MITRE ATT&CK T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting); Microsoft Security Architecture.

## Attack Mechanics
1. Any authenticated domain user requests a Kerberos Ticket Granting Service (TGS) ticket for a domain service account configured with a ServicePrincipalName (`SPN`).
2. The domain controller (KDC) encrypts the TGS ticket using the NTLM or AES key derived from the target service account's password.
3. The attacker extracts the ticket from memory and cracks the password hash completely offline (Hashcat mode 13100 for RC4-HMAC, mode 19600 for AES-128, mode 19700 for AES-256).

## Detection Signatures (EventID 4769)
Windows Security EventID `4769` (A Kerberos service ticket was requested) where `Ticket Options` contains `0x40810000` and `Ticket Encryption Type` is `0x17` (RC4-HMAC-MD5).

## Remediation Protocol
- Transition service accounts to **Group Managed Service Accounts (gMSA)** with 128-char automated rotation.
- Enforce >=25 char complex passwords for non-gMSA service accounts.
- Disable RC4 encryption domain-wide; enforce AES-128/AES-256 (`msDS-SupportedEncryptionTypes = 0x18`).
