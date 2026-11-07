---
title: "Digital Evidence Handling & Chain of Custody (ISO/IEC 27037)"
tags: ["incident-response", "forensics", "chain-of-custody", "evidence", "iso27037"]
source: "ISO/IEC 27037:2012 / NIST SP 800-86"
---

# Digital Evidence Handling & Chain of Custody (ISO/IEC 27037)
## Source & Authority
ISO/IEC 27037:2012 (Guidelines for identification, collection, acquisition and preservation of digital evidence); NIST SP 800-86.

## Order of Volatility (RFC 3227)
Capture digital artifacts in order of decreasing volatility:
1. Registers, cache memory.
2. Routing tables, ARP cache, process table, kernel statistics, active memory (RAM).
3. Temporary file systems, swap space.
4. Hard disks, persistent storage.
5. Remote logging and monitoring data.
6. Physical configuration and network topology.

## Cryptographic Chain of Custody
- Compute SHA-256 and MD5 hashes of raw forensic images immediately upon capture.
- Verify hash integrity before and after analysis. Store evidence on write-blocked media.
