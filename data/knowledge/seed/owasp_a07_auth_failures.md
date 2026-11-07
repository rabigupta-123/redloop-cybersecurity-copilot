---
title: "OWASP Top 10 A07:2021 Identification & Authentication Failures"
tags: ["owasp", "a07", "authentication", "mfa", "passwords", "brute-force"]
source: "OWASP Top 10:2021 A07 / NIST SP 800-63B"
---

# OWASP Top 10 A07:2021 Identification & Authentication Failures
## Source & Authority
OWASP Top 10:2021 Category A07; NIST SP 800-63B (Digital Identity Guidelines).

## Defensive Controls
1. **Multi-Factor Authentication (MFA):** Enforce phishing-resistant MFA (FIDO2 / WebAuthn) for all users.
2. **Brute Force & Credential Stuffing Defenses:** Implement exponential backoff, rate limiting per IP and per username, and CAPTCHA / bot challenge gates.
3. **Session Management:** Invalidate session identifiers on logout and privilege change. Set idle timeout (15-30 min) and maximum session lifespan.
