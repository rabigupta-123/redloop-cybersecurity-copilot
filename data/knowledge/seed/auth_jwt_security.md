---
title: "JSON Web Token (JWT) Security & Implementation Best Practices"
tags: ["auth", "jwt", "tokens", "rfc7519", "api-security"]
source: "RFC 7519 (JSON Web Token) / RFC 8725 (JWT Best Current Practices)"
---

# JSON Web Token (JWT) Security & Implementation Best Practices
## Source & Authority
IETF RFC 7519 (JSON Web Token); IETF RFC 8725 (JWT Best Current Practices).

## Critical Vulnerabilities & Defenses
1. **Algorithm Confusion (`alg: none` & HMAC vs RSA):** Never trust the `alg` header from the client. The verification server must enforce an explicit allowlist of algorithms (e.g. `RS256` or `ES256`). Block `none` and reject tokens signed with asymmetric public keys against HMAC verifiers.
2. **JWKS & Key Injection Attacks (`jku`, `jwk`, `kid`):** Do not load public keys from untrusted client-supplied URLs (`jku`). Restrict `kid` lookups to parameterized queries or static in-memory maps to prevent SQLi or directory traversal.
3. **Mandatory Claim Validation:** Always validate `iss` (issuer), `aud` (audience), `exp` (expiration timestamp), and `nbf` (not before). Enforce short token lifespans (5 to 15 minutes) and issue refresh tokens with rotation and reuse detection.
4. **Token Storage:** In browser clients, avoid `localStorage` (vulnerable to XSS). Store tokens in `HttpOnly`, `Secure`, `SameSite=Strict` cookies.
