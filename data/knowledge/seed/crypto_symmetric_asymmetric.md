---
title: "Symmetric vs Asymmetric Cryptography: Standards & Use Cases"
tags: ["cryptography", "aes", "rsa", "ecc", "ed25519", "nist"]
source: "NIST SP 800-175B Rev 1 (Guideline for Using Cryptographic Standards)"
---

# Symmetric vs Asymmetric Cryptography: Standards & Use Cases
## Source & Authority
NIST SP 800-175B Rev 1 (Guideline for Using Cryptographic Standards: Cryptographic Mechanisms).

## Comparison & Standards
| Type | Symmetric Cryptography | Asymmetric Cryptography |
| :--- | :--- | :--- |
| **Key Architecture** | Single shared secret key for encryption & decryption | Public key for encryption/verify; private key for decrypt/sign |
| **Approved Algorithms** | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 | RSA-3072/4096, ECDSA (P-256/P-384), Ed25519 |
| **Performance** | Extremely fast (hardware AES-NI acceleration) | Computationally expensive (100x to 1000x slower) |
| **Primary Use Cases** | Bulk data encryption at rest and in transit | Key exchange (ECDH), digital signatures, authentication |
