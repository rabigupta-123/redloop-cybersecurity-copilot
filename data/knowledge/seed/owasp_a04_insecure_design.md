---
title: "OWASP Top 10 A04:2021 Insecure Design & Threat Modeling"
tags: ["owasp", "a04", "threat-modeling", "stride", "architecture"]
source: "OWASP Top 10:2021 A04 / IEEE Center for Secure Design"
---

# OWASP Top 10 A04:2021 Insecure Design & Threat Modeling
## Source & Authority
OWASP Top 10:2021 Category A04 (Insecure Design); Microsoft STRIDE Threat Modeling.

## Threat Modeling with STRIDE
Evaluate systems across six threat categories:
- **S (Spoofing):** Authenticate identity tokens and clients.
- **T (Tampering):** Enforce data integrity with digital signatures and HMAC.
- **R (Repudiation):** Implement non-repudiation with append-only audit ledgers.
- **I (Information Disclosure):** Enforce encryption and strict authorization boundaries.
- **D (Denial of Service):** Implement rate limiting and resource throttling.
- **E (Elevation of Privilege):** Enforce least privilege and defense in depth.
