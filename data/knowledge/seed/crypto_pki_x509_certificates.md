---
title: "Public Key Infrastructure (PKI) & X.509 Certificate Validation"
tags: ["cryptography", "pki", "x509", "certificates", "ocsp", "crl"]
source: "RFC 5280 (Internet X.509 Public Key Infrastructure Certificate Profile)"
---

# Public Key Infrastructure (PKI) & X.509 Certificate Validation
## Source & Authority
IETF RFC 5280 (Internet X.509 Public Key Infrastructure Certificate Profile); CA/Browser Forum Baseline Requirements.

## Validation Pipeline
1. **Chain of Trust Verification:** Trace certificate signature through intermediate CAs up to a trusted Root CA in the system trust store.
2. **Validity Window:** Check `notBefore` <= CurrentTime <= `notAfter`.
3. **Revocation Status:** Check Online Certificate Status Protocol (OCSP) or Certificate Revocation Lists (CRLs). Enforce OCSP Stapling (RFC 6066).
4. **Subject Alternative Name (SAN):** Verify that the connecting hostname exactly matches a DNS entry in the SAN extension.
