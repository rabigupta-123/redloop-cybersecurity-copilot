---
title: "Cryptographic Hashing & Modern Password Storage Standards"
tags: ["cryptography", "hashing", "passwords", "argon2", "bcrypt", "sha256"]
source: "RFC 9106 (Argon2) / NIST SP 800-63B / OWASP Password Storage Cheat Sheet"
---

# Cryptographic Hashing & Modern Password Storage Standards
## Source & Authority
IETF RFC 9106 (Argon2 Memory-Hard Function); NIST SP 800-63B Section 5.1.1.2; OWASP Password Storage Cheat Sheet.

## Hashing Types & Applications
1. **Cryptographic Hashes (Fast):** SHA-256, SHA-384, SHA-512, SHA-3. Designed for collision resistance and fast execution. Ideal for data integrity verification, digital signatures, and HMAC. **NEVER use for passwords.**
2. **Password Hashing Functions (Slow & Memory-Hard):**
   - **Argon2id (Winner of Password Hashing Competition - Recommended):** Memory-hard and time-hard; resistant to GPU and ASIC cracking attacks. (Parameters: memory >= 64MB, iterations >= 3, parallelism = 4).
   - **bcrypt:** Time-tested work-factor adjustable hashing. (Work factor >= 12).
   - **PBKDF2-HMAC-SHA256:** Minimum 600,000 iterations per OWASP recommendations.
