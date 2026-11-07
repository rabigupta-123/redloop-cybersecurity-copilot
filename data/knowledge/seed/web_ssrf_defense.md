---
title: "Server-Side Request Forgery (SSRF) Mechanics & Prevention"
tags: ["web", "ssrf", "owasp", "cloud", "defense", "cwe918"]
source: "OWASP Top 10 A10:2021 / CWE-918 / RFC 3986"
---

# Server-Side Request Forgery (SSRF) Mechanics & Prevention
## Source & Authority
OWASP Top 10:2021 A10; Common Weakness Enumeration CWE-918; RFC 3986 (URI Generic Syntax).

## Threat Mechanics
An attacker induces the server-side application to make HTTP requests to an unintended location, such as internal loopback interfaces (`127.0.0.1`), RFC 1918 private subnets, or cloud instance metadata endpoints (`169.254.169.254`).

## Defense-in-Depth Implementation
1. **Fail-Closed IP Validation & Resolution Pinning:**
   - Parse and normalize the destination URL with strict scheme validation (`http`, `https` only).
   - Resolve the target hostname to an IP address using `getaddrinfo` BEFORE making the socket connection.
   - Validate the resolved IP against an explicit blocklist: reject loopback (`127.0.0.0/8`, `::1`), RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and multicast.
   - Pin the validated IP address to the outbound connection to prevent DNS Rebinding (TOCTOU) attacks.
2. **Cloud Metadata Hardening:** Enforce AWS IMDSv2 (`http-tokens=required`, hop limit 1) to eliminate token exfiltration via SSRF.
3. **Disable Unused Protocols:** Disable URL schemes `file://`, `gopher://`, `dict://`, `ftp://`.
