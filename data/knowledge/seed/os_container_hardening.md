---
title: "Docker & Kubernetes Container Security Hardening"
tags: ["os", "containers", "docker", "kubernetes", "cloud-native"]
source: "CIS Docker Benchmark / NIST SP 800-190"
---

# Docker & Kubernetes Container Security Hardening
## Source & Authority
CIS Docker Benchmark; NIST SP 800-190 (Application Container Security Guide).

## Core Security Controls
1. **Rootless Execution:** Never run container processes as UID 0 (`root`). Enforce `USER 10001` in Dockerfile.
2. **Immutable Filesystem:** Mount root filesystem as read-only (`--read-only` or `securityContext.readOnlyRootFilesystem: true`).
3. **Drop Capabilities:** Drop all default Linux capabilities and add only required primitives (`cap_drop: ["ALL"]`, `cap_add: ["NET_BIND_SERVICE"]`).
4. **Prevent Privilege Escalation:** Enforce `allowPrivilegeEscalation: false` to block setuid binaries.
5. **Seccomp & AppArmor:** Apply default runtime seccomp profile (`RuntimeDefault`) to restrict syscall execution.
