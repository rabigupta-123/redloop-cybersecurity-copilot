---
title: "OWASP Top 10 A08:2021 Software and Data Integrity Failures"
tags: ["owasp", "a08", "integrity", "ci-cd", "code-signing", "supply-chain"]
source: "OWASP Top 10:2021 A08 / SLSA Framework"
---

# OWASP Top 10 A08:2021 Software and Data Integrity Failures
## Source & Authority
OWASP Top 10:2021 Category A08; SLSA (Supply-chain Levels for Software Artifacts) Framework.

## Core Controls
1. **Code & Artifact Signing:** Digitally sign all releases, packages, and container images using Sigstore (Cosign) with verifiable transparency logs (Rekor).
2. **CI/CD Hardening:** Enforce branch protection rules, require signed commits, and use isolated ephemeral runners with minimal token permissions.
3. **Subresource Integrity (SRI):** Enforce `integrity="sha384-..."` attributes on third-party scripts loaded in web browsers.
