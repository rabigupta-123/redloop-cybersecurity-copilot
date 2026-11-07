---
title: "Linux Kernel & Operating System Hardening Framework"
tags: ["os", "linux", "kernel", "hardening", "sysctl", "apparmor"]
source: "CIS Linux Benchmark / NIST SP 800-123"
---

# Linux Kernel & Operating System Hardening Framework
## Source & Authority
CIS Linux Benchmarks; NIST SP 800-123 (Guide to General Server Security).

## Critical Kernel Parameters (`/etc/sysctl.d/99-security.conf`)
```ini
# Enforce Address Space Layout Randomization (ASLR)
kernel.randomize_va_space = 2

# Restrict ptrace execution to admin
kernel.yama.ptrace_scope = 2

# Hide kernel pointers in /proc
kernel.kptr_restrict = 2

# Restrict dmesg output to privileged users
kernel.dmesg_restrict = 1

# Protect against SYN flood DoS
net.ipv4.tcp_syncookies = 1

# Disable IP source routing and packet forwarding
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.ip_forward = 0

# Enable reverse path filtering (spoofing protection)
net.ipv4.conf.all.rp_filter = 1
```

## Mandatory Access Control
Enforce AppArmor or SELinux in `enforcing` mode on all production workloads.
