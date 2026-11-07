---
title: "Incident Response Lifecycle (NIST SP 800-61 Rev 2)"
tags: ["incident-response", "nist", "lifecycle", "containment", "remediation"]
source: "NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide)"
---

# Incident Response Lifecycle (NIST SP 800-61 Rev 2)
## Source & Authority
NIST Special Publication 800-61 Rev 2 (Computer Security Incident Handling Guide).

## Four Phases of Incident Handling
1. **Preparation:** Establish incident response policy, defined roles (CSIRT), secure communication channels, pre-configured forensic tooling, and verified out-of-band contact trees.
2. **Detection & Analysis:** Triage alerts from SIEM, EDR, and network sensors. Determine incident scope, attack vector, impacted assets, and preliminary severity rating.
3. **Containment, Eradication & Recovery:**
   - *Short-Term Containment:* Isolate compromised systems from network; revoke compromised access tokens.
   - *Long-Term Containment:* Deploy temporary firewall filters, virtual patching at WAF, credential resets.
   - *Eradication:* Remove malware, backdoors, and persistence mechanisms (registry run keys, scheduled tasks).
   - *Recovery:* Restore validated clean backups, re-enable services, and implement heightened monitoring.
4. **Post-Incident Activity (Lessons Learned):** Complete root-cause analysis, document findings, and update detection rules and standard operating procedures within 14 days of closure.
