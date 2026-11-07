---
title: "Cross-Origin Resource Sharing (CORS) Security & Misconfigurations"
tags: ["web", "cors", "owasp", "browser-security", "rfc6454"]
source: "W3C CORS Specification / RFC 6454 (The Web Origin Concept)"
---

# Cross-Origin Resource Sharing (CORS) Security & Misconfigurations
## Source & Authority
W3C CORS Specification; IETF RFC 6454 (The Web Origin Concept).

## Vulnerability Patterns
1. **Reflected Origin with Credentials:** Mirroring the request's `Origin` header into `Access-Control-Allow-Origin` while returning `Access-Control-Allow-Credentials: true`. Allows malicious websites to perform authenticated cross-origin reads of victim data.
2. **Trusting `null` Origin:** Setting `Access-Control-Allow-Origin: null`. Sandboxed iframes, local HTML files, and data: URIs run with origin `null` and can exfiltrate sensitive data.
3. **Insecure Wildcard or Weak Regex:** Using unanchored regular expressions (e.g. matching `example.com` instead of `^https://(?:[a-z0-9-]+\.)?example\.com$`) allows domains like `attacker-example.com` to pass checks.

## Secure Configuration
- Maintain a strict server-side allowlist of trusted origins.
- Never set `Access-Control-Allow-Origin: *` when credentials (`cookies`, `Authorization` headers) are supported.
