---
title: "Compromised Credential Remediation & Session Revocation"
tags: ["incident-response", "credentials", "identity", "revocation", "active-directory"]
source: "NIST SP 800-63B / Microsoft Security Guidelines"
---

# Compromised Credential Remediation & Session Revocation
## Source & Authority
NIST SP 800-63B (Digital Identity Guidelines: Authentication and Lifecycle Management); Microsoft Incident Response.

## Immediate Action Items
1. **Terminate Active Sessions:** Revoke all active OAuth refresh tokens and terminate web sessions across Microsoft 365 / Azure AD (`Revoke-AzureADUserAllRefreshToken`) or Okta.
2. **Password Invalidation:** Reset user password enforcing maximum complexity.
3. **MFA Audit:** Inspect registered MFA devices (FIDO2 keys, Authenticator apps, phone numbers). Attackers frequently register secondary MFA devices during unauthorized access.
4. **Kerberos Invalidation:** In on-premise AD, reset user password twice to invalidate current Kerberos TGT and TGS tickets.
5. **Mailbox Rules Audit:** Check for illicit forwarding or hide-rule filters created in Exchange/Gmail (`Get-InboxRule`).
