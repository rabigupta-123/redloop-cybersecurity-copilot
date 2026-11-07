---
title: "Active Directory Certificate Services (AD CS) Security (ESC1-ESC8)"
tags: ["active-directory", "adcs", "certificates", "pki", "esc1"]
source: "SpecterOps Certified Pre-Owned Research / Microsoft KB5005408"
---

# Active Directory Certificate Services (AD CS) Security (ESC1-ESC8)
## Source & Authority
SpecterOps "Certified Pre-Owned" Research; Microsoft Security Guidance on Certificate Mapping (KB5005408).

## Critical Vulnerability Vectors
- **ESC1 (Subject Alternative Name Request):** Certificate template allows low-privileged domain users to enroll (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) and includes Client Authentication EKU. An attacker requests a certificate specifying a Domain Admin's User Principal Name (UPN) in the SAN, authenticating as Domain Admin via PKINIT.
- **ESC8 (NTLM Relay to AD CS HTTP Web Enrollment):** Relaying captured NTLM credentials to unhardened AD CS HTTP web enrollment endpoints (`/certsrv/`).

## Remediation Protocol
1. Uncheck `Supply in the request` on all certificate templates that include client authentication.
2. Enforce Extended Protection for Authentication (EPA) and require HTTPS on all AD CS Web Enrollment servers.
3. Audit templates with `Certify` or `PKIAudit`.
