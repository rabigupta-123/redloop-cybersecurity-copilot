---
title: "Kerberos Protocol Fundamentals & Windows Authentication"
tags: ["auth", "kerberos", "active-directory", "windows", "tickets"]
source: "RFC 4120 (The Kerberos Network Authentication Service) / MS-KILE"
---

# Kerberos Protocol Fundamentals & Windows Authentication
## Source & Authority
IETF RFC 4120; Microsoft MS-KILE (Kerberos Protocol Extensions).

## Authentication Flow
1. **AS-REQ / AS-REP:** Client sends an Authentication Service Request (`KRB_AS_REQ`) with timestamp encrypted with user password hash (pre-authentication). Key Distribution Center (KDC) validates and returns Ticket Granting Ticket (`TGT`) encrypted with `KRBTGT` key (`KRB_AS_REP`).
2. **TGS-REQ / TGS-REP:** Client presents TGT to request service access (`KRB_TGS_REQ`). KDC verifies TGT and issues Ticket Granting Service (`TGS`) ticket encrypted with target service account's secret key.
3. **AP-REQ / AP-REP:** Client delivers TGS ticket to the target application server (`KRB_AP_REQ`) to authenticate without exposing user credentials.

## Attack Surface & Defenses
- **Kerberoasting:** Attackers request TGS tickets for Service Principal Names (SPNs) and crack them offline. Mitigate with Group Managed Service Accounts (gMSA) or >=25 char complex passwords.
- **AS-REP Roasting:** Targeting accounts with `DONT_REQ_PREAUTH`. Enforce pre-authentication domain-wide.
- **Golden / Silver Tickets:** Compromise of KRBTGT hash enables forged TGTs (Golden Ticket). Mitigate by rotating the KRBTGT password twice.
