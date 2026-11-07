---
title: "Insecure Direct Object Reference (IDOR) & Object Authorization"
tags: ["web", "idor", "authorization", "owasp", "cwe639"]
source: "OWASP Top 10 A01:2021 / CWE-639"
---

# Insecure Direct Object Reference (IDOR) & Object Authorization
## Source & Authority
OWASP Top 10:2021 A01 (Broken Access Control); Common Weakness Enumeration CWE-639.

## Threat Mechanics
An application uses user-supplied input to access database records, files, or internal objects directly without verifying that the authenticated user possesses authorization to act on that specific resource (e.g. `/api/invoices/1042` accessed by user `1043`).

## Remediation Architecture
1. **Contextual Object-Level Authorization:** At the database query level, bind data access to the authenticated user ID (`SELECT * FROM invoices WHERE id = ? AND tenant_id = ?`).
2. **Indirect Reference Mapping:** Use random GUIDs (UUID v4) or session-specific indirect reference maps rather than predictable sequential integer primary keys.
3. **Automated Access Control Tests:** Enforce unit and integration tests verifying cross-tenant and horizontal privilege separation.
