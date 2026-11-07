---
title: "OWASP Top 10 A09:2021 Security Logging & Monitoring Failures"
tags: ["owasp", "a09", "logging", "monitoring", "siem", "audit"]
source: "OWASP Top 10:2021 A09 / NIST SP 800-92"
---

# OWASP Top 10 A09:2021 Security Logging & Monitoring Failures
## Source & Authority
OWASP Top 10:2021 Category A09; NIST SP 800-92 (Guide to Computer Security Log Management).

## Essential Practices
1. **Comprehensive Event Logging:** Log all authentication successes and failures, access control failures, server-side input validation errors, and administrative actions.
2. **Log Integrity & Tamper Proofing:** Forward logs in real-time to an append-only, tamper-evident central log collector. Sign log hashes.
3. **Prevent Log Injection & Data Leaks:** Sanitize newline characters (`\r`, `\n`) from log messages to prevent log forging. Redact passwords, credit card numbers, and API tokens before logging.
