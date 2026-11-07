---
title: "OWASP Top 10 A02:2021 Cryptographic Failures & Protection"
tags: ["owasp", "a02", "cryptography", "encryption", "tls"]
source: "OWASP Top 10:2021 A02 / CWE-310"
---

# OWASP Top 10 A02:2021 Cryptographic Failures & Protection
## Source & Authority
OWASP Top 10:2021 Category A02 (Cryptographic Failures); CWE-310.

## Core Rules
1. Encrypt all sensitive data in transit using modern TLS (TLS 1.3 preferred, minimum TLS 1.2 with AEAD ciphers).
2. Enforce HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`).
3. Store passwords using salted, work-factor adjustable password hashes (Argon2id, bcrypt). Never use MD5, SHA-1, or plain SHA-256 for passwords.
4. Use cryptographically secure pseudo-random number generators (`secrets` in Python, `crypto.randomBytes()` in Node.js) rather than standard PRNGs (`random.random()`).
