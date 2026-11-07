---
title: "AWS KMS Cryptographic Key Management & Policies"
tags: ["cloud", "aws", "kms", "cryptography", "encryption", "keys"]
source: "NIST SP 800-57 Part 1 / FIPS 140-3 Cryptographic Standards"
---

# AWS KMS Cryptographic Key Management & Policies
## Source & Authority
NIST SP 800-57 Part 1 (Recommendation for Key Management); FIPS 140-3 Security Requirements for Cryptographic Modules.

## Architecture & Controls
1. **Customer Managed Keys (CMKs):** Utilize CMKs instead of AWS-managed keys to maintain full governance over key policies, access revocation, and annual rotation schedules.
2. **Key Policy Separation:** Separate key administration (`kms:Create*`, `kms:PutKeyPolicy`) from cryptographic usage (`kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`). Key administrators must not have blanket decrypt permissions.
3. **Envelope Encryption:** Applications generate high-performance plaintext data keys locally, encrypt large payloads with AES-256-GCM, and store the KMS-ciphertext encrypted data key alongside the payload.
4. **Auditing & Break-Glass:** Monitor `kms:Decrypt` anomalies in CloudTrail. High-rate decrypt spikes indicate data exfiltration.
