---
title: "OpenSSH Server Cryptographic & Operational Hardening"
tags: ["os", "ssh", "linux", "hardening", "crypto", "network"]
source: "NIST SP 800-123 / Mozilla OpenSSH Modern Security Guidelines"
---

# OpenSSH Server Cryptographic & Operational Hardening
## Source & Authority
NIST SP 800-123; Mozilla OpenSSH Modern Security Guidelines; CIS Benchmark.

## Configuration (`/etc/ssh/sshd_config`)
```ini
# Disable root login and passwords
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes

# Limit attempts and authentication timeout
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Modern Cryptographic Primitives (Disable SHA-1, DSA, 3DES, CBC)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKey /etc/ssh/ssh_host_ed25519_key
```
