---
title: "Ransomware Containment & Recovery Playbook"
tags: ["incident-response", "ransomware", "playbook", "containment", "recovery"]
source: "CISA Ransomware Guide / NIST SP 800-61r2"
---

# Ransomware Containment & Recovery Playbook
## Source & Authority
CISA / MS-ISAC Joint Ransomware Guide; NIST SP 800-61 Rev 2.

## Emergency Containment Protocol
1. **Network Isolation:** Sever all network connections for impacted endpoints immediately (disable physical NIC, disconnect Wi-Fi, apply EDR network containment). Do NOT power down or reboot machines (preserves volatile memory and encryption keys).
2. **Active Directory Triage:** If domain controllers are compromised, isolate them to prevent domain-wide GPO-driven ransomware distribution.
3. **Backup Protection:** Disconnect backup infrastructure from network immediately to prevent attacker deletion or encryption of shadow copies and air-gapped repositories.
4. **Credential Revocation:** Reset all Active Directory administrative credentials, service accounts, and rotate the `KRBTGT` password twice.
5. **Clean Restoration:** Rebuild systems from verified gold images and restore data only from clean, offline backups verified prior to dwell time initiation.
