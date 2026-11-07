---
title: "Windows Endpoint & Server Hardening Best Practices"
tags: ["os", "windows", "hardening", "endpoint", "defender", "asr"]
source: "CIS Microsoft Windows Server Benchmark / NIST SP 800-41"
---

# Windows Endpoint & Server Hardening Best Practices
## Source & Authority
CIS Microsoft Windows Server Benchmarks; NIST SP 800-41; Microsoft Security Baselines.

## Baseline Controls
1. **Attack Surface Reduction (ASR) Rules:** Enforce blocking rules via Intune or GPO:
   - Block executable content from email client and webmail.
   - Block all Office applications from creating child processes.
   - Block Office applications from injecting code into other processes.
   - Block credential stealing from Windows Local Security Authority Subsystem (`lsass.exe`).
2. **Credential Guard & LSA Protection:** Enable virtualization-based security (VBS) and Credential Guard to isolate LSASS secrets in a protected hypervisor enclave.
3. **Application Control:** Deploy Windows Defender Application Control (WDAC) or AppLocker in enforce mode to block untrusted executables, DLLs, and scripts.
4. **Disable Insecure Protocols:** Disable SMBv1, LLMNR, NetBIOS over TCP/IP, and digest authentication.
