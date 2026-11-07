---
title: "OWASP Top 10 A01:2021 Broken Access Control Architecture"
tags: ["owasp", "a01", "access-control", "authorization", "rbac"]
source: "OWASP Top 10:2021 A01 / CWE-284"
---

# OWASP Top 10 A01:2021 Broken Access Control Architecture
## Source & Authority
OWASP Top 10:2021 Category A01 (Broken Access Control); CWE-284.

## Root Causes & Mitigation
- **Deny by Default:** Design authorization systems to reject access unless explicit permissions are granted.
- **Enforce Role-Based and Attribute-Based Access Control (RBAC/ABAC):** Evaluate permissions server-side on every request; never rely on UI hiding or client-side checks.
- **Disable Directory Browsing:** Ensure web server directory indexing is disabled on all public endpoints.
