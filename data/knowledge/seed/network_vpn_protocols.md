---
title: "VPN Protocol Comparison: WireGuard vs OpenVPN vs IPsec"
tags: ["network", "vpn", "wireguard", "ipsec", "openvpn"]
source: "RFC 7296 (IKEv2) / WireGuard Technical Whitepaper"
---

# VPN Protocol Comparison: WireGuard vs OpenVPN vs IPsec
## Source & Authority
IETF RFC 7296 (Internet Key Exchange Protocol Version 2 - IKEv2); WireGuard Technical Whitepaper (Jason A. Donenfeld).

## Technical Comparison
| Metric | WireGuard | OpenVPN | IPsec (IKEv2) |
| :--- | :--- | :--- | :--- |
| **Codebase Size** | ~4,000 lines (Auditable) | ~70,000+ lines | ~100,000+ lines |
| **Cryptography** | Fixed Modern: Noise, Curve25519, ChaCha20-Poly1305, BLAKE2s | Agile (OpenSSL): AES, Camellia, RSA, ECC | Agile: AES-GCM, SHA2, Diffie-Hellman groups |
| **Kernel Integration** | In-tree Linux kernel module (ultra fast) | Userspace TUN/TAP daemon | Kernel-level XFRM framework |
| **Handshake Latency** | Instantaneous connection / reconnection | Multi-second TLS handshake | Moderate IKE negotiation |
| **Mobility & Roaming**| Built-in (IP roaming via cryptographic cookie) | Requires reconnect | MOBIKE (RFC 4555) extension |
