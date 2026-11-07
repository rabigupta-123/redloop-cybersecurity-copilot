---
title: "BGP Hijacking, Route Leaks & RPKI ROV Security"
tags: ["network", "bgp", "routing", "rpki", "internet-security"]
source: "RFC 4271 (BGP-4) / RFC 6480 (An Infrastructure to Support Secure Internet Routing)"
---

# BGP Hijacking, Route Leaks & RPKI ROV Security
## Source & Authority
IETF RFC 4271 (A Border Gateway Protocol 4); RFC 6480 (RPKI Architecture); RFC 6811 (BGP Prefix Origin Validation).

## Vulnerability Mechanics
BGP natively trusts route announcements between autonomous systems (AS). A rogue or misconfigured AS can announce more specific IP prefixes (e.g. `/24` instead of `/16`) or spoof the AS-Path, hijacking global internet traffic.

## RPKI & BGPSec Remediation
1. **Resource Public Key Infrastructure (RPKI):** Network operators publish cryptographically signed Route Origin Authorizations (ROAs) binding an IP prefix to an authorized Autonomous System Number (ASN) and maximum prefix length.
2. **Route Origin Validation (ROV):** Border routers drop announcements evaluated as `Invalid` according to verified ROA cryptographic state.
