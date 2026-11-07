---
title: "DNS Attack Vectors & Cryptographic Defenses (DNSSEC)"
tags: ["network", "dns", "dnssec", "cache-poisoning", "rebinding"]
source: "RFC 4033 / RFC 5452 (Measures for Making DNS More Resilient)"
---

# DNS Attack Vectors & Cryptographic Defenses (DNSSEC)
## Source & Authority
IETF RFC 4033 (DNS Security Introduction); RFC 5452 (Measures for Making DNS More Resilient against Forgery).

## Common Attack Vectors
1. **DNS Cache Poisoning:** Forging DNS responses to inject malicious A records into caching recursive resolvers. Mitigated by source port randomization (16 bits) and transaction ID randomization (16 bits), and fully solved by DNSSEC.
2. **DNS Tunneling:** Encapsulating non-DNS protocols inside DNS TXT or A queries/responses to bypass egress firewall filtering. Detected via Shannon entropy analysis of query names and request frequency.
3. **DNS Rebinding:** An external web page points a hostname to an external IP, then rapidly shifts DNS resolution to `127.0.0.1` with a low TTL (0s), bypassing the Same-Origin Policy.
4. **DNSSEC:** Cryptographically signs DNS resource record sets (RRsets) with RRSIG records verified through a chain of trust back to the root trust anchor (DS records).
