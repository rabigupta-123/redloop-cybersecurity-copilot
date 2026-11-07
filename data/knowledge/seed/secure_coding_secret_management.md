---
title: "Secure Coding: Secrets Hygiene & Key Management in CI/CD"
tags: ["secure-coding", "secrets", "ci-cd", "git", "api-keys"]
source: "NIST SP 800-57 / OWASP Secrets Management Cheat Sheet"
---

# Secure Coding: Secrets Hygiene & Key Management in CI/CD
## Source & Authority
NIST SP 800-57; OWASP Secrets Management Cheat Sheet.

## Core Rules
1. **Never Commit Secrets to Version Control:** Enforce pre-commit hooks (`gitleaks`, `trufflehog`) to scan for API keys (`sk-*`, `gsk_*`, AWS keys) before code commits.
2. **Load Secrets from Environment or Vault:** Load secrets dynamically via environment variables or secret managers (HashiCorp Vault, AWS Secrets Manager, Doppler).
3. **Rotate Immediately on Exposure:** If a secret is committed to git history, treat it as compromised immediately: revoke and rotate the secret, and audit access logs.
