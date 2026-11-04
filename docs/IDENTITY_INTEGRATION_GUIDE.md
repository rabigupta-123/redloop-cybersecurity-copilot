# Identity Providers Integration Guide (Microsoft Entra ID & Active Directory)

## Overview

The REDLOOP Identity Gateway enables deep identity telemetry correlation and automated response actions across:
1. **Microsoft Entra ID (Azure AD)** via Microsoft Graph API.
2. **On-Premises Active Directory Domain Services** via LDAPS protocol.

---

## 1. Capabilities Supported

### Microsoft Entra ID:
- `LOOKUP_USER`: Resolves user principal name (UPN), accountEnabled status, department, and ID.
- `GET_AUTH_EVENTS`: Ingests sign-in logs and authentication anomalies.
- `REVOKE_USER_SESSIONS`: Revokes all active OAuth refresh tokens and sign-in sessions (Approval-Gated).

### Active Directory (LDAP):
- `LOOKUP_USER`: Resolves user object attributes via LDAP search filter.
- `DISABLE_USER_ACCOUNT`: Sets account disabled flag (`userAccountControl` bit 0x0002) to lock compromised accounts (Approval-Gated).

---

## 2. Approval Protection for Account Lockout & Session Revocation

High-impact identity actions (disabling an account, revoking active sessions across all devices) are strictly approval-gated:
- Both `revoke_sessions` and `disable_account` require a non-empty `capability_token`.
- Without a token, the action returns `WAITING_FOR_APPROVAL` without executing any LDAP modify or Graph API operations.
- Capabilities are cryptographically bound to the target UPN / sAMAccountName and verified atomically.
