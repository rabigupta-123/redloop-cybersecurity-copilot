---
title: "OWASP Top 10 A03:2021 Injection Attacks & Universal Prevention"
tags: ["owasp", "a03", "injection", "sqli", "command-injection"]
source: "OWASP Top 10:2021 A03 / CWE-77 / CWE-89"
---

# OWASP Top 10 A03:2021 Injection Attacks & Universal Prevention
## Source & Authority
OWASP Top 10:2021 Category A03 (Injection); CWE-77 (Command Injection); CWE-89 (SQL Injection).

## Core Defense Principles
- **Parameterized Queries:** Always separate untrusted data from the SQL code structure. Use parameterized prepared statements or safe ORM mappers.
- **Avoid Shell Execution:** Do NOT invoke operating system shells (`shell=True` in Python, `exec()` / `system()`). Use array-based subprocess invocations with full path binaries.
- **Context-Aware Input Validation:** Enforce strict allowlist validation on all input fields.
