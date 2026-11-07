---
title: TCP Three-Way Handshake & Connection Security
tags: [tcp, handshake, syn, ack, rfc9293, network, transport-layer]
source: IETF RFC 9293 (Transmission Control Protocol); RFC 4987 (TCP SYN Flooding Attacks and Defenses)
---

# TCP Three-Way Handshake & Connection Security

## Source & Authority
IETF RFC 9293 (Transmission Control Protocol, STD 7); RFC 4987 (TCP SYN Flooding Attacks and Common Mitigations); NIST SP 800-115.

## Handshake Architecture
The Transmission Control Protocol (TCP) establishes a reliable, bidirectional, full-duplex byte-stream connection via a synchronized three-way exchange:

1. **Step 1: SYN (Synchronize)**
   - The initiating client sends a TCP segment with the `SYN` control flag set.
   - It chooses an Initial Sequence Number (`ISN_client`), typically generated using a cryptographically secure pseudorandom algorithm to prevent blind spoofing and TCP sequence number guessing attacks (RFC 6528).
   - State transition: Client enters `SYN-SENT`.

2. **Step 2: SYN-ACK (Synchronize-Acknowledge)**
   - The listening server responds with both `SYN` and `ACK` flags set.
   - The acknowledgment number is set to `ISN_client + 1`, confirming receipt of the client's SYN.
   - The server generates its own independent Initial Sequence Number (`ISN_server`).
   - State transition: Server enters `SYN-RECEIVED`.

3. **Step 3: ACK (Acknowledge)**
   - The client completes connection establishment by sending an `ACK` packet with acknowledgment number set to `ISN_server + 1`.
   - The client may optionally begin transmitting application-layer payload data alongside or immediately following this segment.
   - State transition: Both endpoints enter `ESTABLISHED`.

## Security Threats & Mitigations

### 1. TCP SYN Flood Attacks (Resource Exhaustion)
- **Mechanism:** Attackers flood a target port with forged SYN segments while ignoring or discarding incoming SYN-ACK responses. The server allocates transmission control blocks (TCB) in a half-open state table until the backlog queue is exhausted, denying service to legitimate clients.
- **Defenses:**
  - **SYN Cookies (RFC 4987):** Encode connection state parameters cryptographically into the server's `ISN_server` (`timestamp`, `MSS`, `secret-hash(client-ip, client-port, server-ip, server-port)`). State is only committed to kernel memory upon receiving a valid final ACK.
  - **Linux Kernel Hardening:**
    ```sysctl
    net.ipv4.tcp_syncookies = 1
    net.ipv4.tcp_max_syn_backlog = 4096
    net.ipv4.tcp_synack_retries = 2
    ```

### 2. TCP Reset & Hijacking Attacks
- **Mechanism:** An on-path or spoofing attacker injects RST or data packets within the expected sliding sequence window to terminate or manipulate active connections.
- **Defenses:**
  - Strict sequence validation and TCP MD5 Signature Option (RFC 2385) or TCP Authentication Option (TCP-AO, RFC 5925) for critical BGP/infrastructure sessions.
  - Mandatory transport encryption (TLS 1.3 / IPsec) over all untrusted networks.

