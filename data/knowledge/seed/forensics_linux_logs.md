---
title: "Linux Log Forensics: auth.log, syslog & auditd"
tags: ["forensics", "linux", "logs", "auth.log", "auditd", "incident-response"]
source: "NIST SP 800-86 / Red Hat Security Guide"
---

# Linux Log Forensics: auth.log, syslog & auditd
## Source & Authority
NIST SP 800-86; Linux Audit System Documentation (auditd).

## Log Artifact Triage
1. **`/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS):**
   - Failed SSH attempts: `Failed password for invalid user <user> from <ip> port <port> ssh2`.
   - Sudo escalation: `sudo: <user> : TTY=... ; PWD=... ; USER=root ; COMMAND=...`.
2. **`last` & `lastlog`:** Parse `/var/log/wtmp` and `/var/log/btmp` to reconstruct interactive logon timelines and failed login attempts.
3. **Linux Auditd (`ausearch` / `aureport`):**
   - Query syscalls matching process execution: `ausearch -m EXECVE -ts today`.
   - Query file tampering on critical configs: `ausearch -f /etc/shadow`.
