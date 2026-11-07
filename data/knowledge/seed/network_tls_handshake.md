---
title: "TLS 1.3 Protocol Architecture & Handshake Security"
tags: ["network", "tls", "cryptography", "handshake", "rfc8446"]
source: "RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3)"
---

# TLS 1.3 Protocol Architecture & Handshake Security
## Source & Authority
IETF RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3).

## Key Architectural Enhancements
1. **1-RTT Handshake:** Reduces connection setup time from 2 round-trips (TLS 1.2) to 1 round-trip by sending key shares in the initial `ClientHello`.
2. **Removal of Legacy Insecure Primitives:** Completely eliminates static RSA key exchange (ensuring mandatory Ephemeral Diffie-Hellman Perfect Forward Secrecy), CBC mode ciphers, RC4, MD5, and SHA-1.
3. **Approved Cipher Suites:** Restricted to authenticated encryption with associated data (AEAD):
   - `TLS_AES_256_GCM_SHA384`
   - `TLS_CHACHA20_POLY1305_SHA256`
   - `TLS_AES_128_GCM_SHA256`
4. **0-RTT Early Data Risk:** 0-RTT data is vulnerable to replay attacks. Applications must restrict 0-RTT to idempotent GET requests and never allow financial transactions or state changes.
