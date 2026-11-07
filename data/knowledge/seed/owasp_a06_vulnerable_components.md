---
title: "OWASP Top 10 A06:2021 Vulnerable and Outdated Components (SCA & SBOM)"
tags: ["owasp", "a06", "sbom", "dependencies", "sca", "patch-management"]
source: "OWASP Top 10:2021 A06 / NIST SP 800-161"
---

# OWASP Top 10 A06:2021 Vulnerable and Outdated Components (SCA & SBOM)
## Source & Authority
OWASP Top 10:2021 Category A06; NIST SP 800-161 (Cybersecurity Supply Chain Risk Management Practices).

## Implementation
1. **Software Bill of Materials (SBOM):** Generate automated CycloneDX or SPDX SBOMs in CI/CD pipelines to track transitive dependencies.
2. **Software Composition Analysis (SCA):** Run automated scanning tools (Trivy, Grype, pip-audit, npm audit) on every pull request to block known CVEs.
3. **Dependency Pinning:** Pin exact dependency versions with cryptographic hash verification (`requirements.txt --require-hashes` or lockfiles).
