---
title: "MITRE ATT&CK Initial Access (TA0001) Tactics & Defenses"
tags: ["mitre", "initial-access", "t1190", "t1566", "phishing"]
source: "MITRE ATT&CK TA0001"
---

# MITRE ATT&CK Initial Access (TA0001) Tactics & Defenses
## Source & Authority
MITRE ATT&CK Tactic TA0001 (Initial Access).

## Primary Techniques & Mitigations
- **T1190 (Exploit Public-Facing Application):** Exploiting web servers, VPN gateways, or public APIs (e.g. Log4Shell, ProxyLogon). Mitigate with rapid vulnerability patching, attack surface management, and WAF virtual patching.
- **T1566 (Phishing):** Spearphishing attachments or credential harvesting links. Mitigate with DMARC enforcement, email attachment sandboxing, and Phishing-Resistant FIDO2 MFA.
- **T1078 (Valid Accounts):** Compromising legitimate credentials via infostealers or password reuse. Mitigate with conditional access, MFA, and abnormal sign-in behavioral alerting.
