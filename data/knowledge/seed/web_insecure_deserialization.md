---
title: "Insecure Deserialization Vulnerabilities & Safe Practices"
tags: ["web", "deserialization", "owasp", "rce", "cwe502"]
source: "OWASP Top 10 A08:2021 / CWE-502"
---

# Insecure Deserialization Vulnerabilities & Safe Practices
## Source & Authority
OWASP Top 10:2021 A08 (Software and Data Integrity Failures); CWE-502.

## Threat Mechanics
Deserialization occurs when structured byte streams or strings are converted back into memory objects. If untrusted input is deserialized using native object deserializers (Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, .NET `BinaryFormatter`), an adversary can trigger execution of existing code paths ('gadget chains') leading to Remote Code Execution (RCE).

## Defensive Controls
1. **Never Deserialize Untrusted Data with Native Object Deserializers:** Ban `pickle.loads()`, Java native serialization, and PHP `unserialize()` on user data.
2. **Cryptographic Signing (HMAC):** If serialized data must transit the client, sign the payload using HMAC-SHA256 with a secure server-side secret; verify signature before unpacking.
3. **Use Safe Structured Data Formats:** Enforce strict data-only formats: JSON, Protocol Buffers, or MessagePack.
