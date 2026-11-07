---
title: "OWASP Top 10 A05:2021 Security Misconfiguration Hardening"
tags: ["owasp", "a05", "misconfiguration", "hardening", "headers"]
source: "OWASP Top 10:2021 A05 / CIS Benchmarks"
---

# OWASP Top 10 A05:2021 Security Misconfiguration Hardening
## Source & Authority
OWASP Top 10:2021 Category A05 (Security Misconfiguration); CIS Benchmarks.

## Key Hardening Areas
1. **Disable Default Accounts & Passwords:** Remove or disable default user accounts and change all default factory credentials immediately.
2. **Error Handling:** Disable verbose debug error pages (`DEBUG = False` in Django/Flask) that expose stack traces, database schema, or environment variables.
3. **Mandatory Security Headers:**
   - `Content-Security-Policy: default-src 'self'`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
