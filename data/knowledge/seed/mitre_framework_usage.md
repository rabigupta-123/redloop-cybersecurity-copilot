---
title: "MITRE ATT&CK Framework Architecture & Operational Usage"
tags: ["mitre", "attack", "framework", "threat-intel", "soc"]
source: "MITRE ATT&CK Enterprise Matrix v14"
---

# MITRE ATT&CK Framework Architecture & Operational Usage
## Source & Authority
MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) v14.

## Taxonomy Structure
- **Tactics:** The adversary's technical objective (the "why"): e.g. Initial Access (TA0001), Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005), Credential Access (TA0006), Lateral Movement (TA0008), Exfiltration (TA0010).
- **Techniques:** How the adversary achieves a tactical goal (the "what"): e.g. T1059 (Command and Scripting Interpreter).
- **Sub-Techniques:** Specific implementations: e.g. T1059.001 (PowerShell), T1059.003 (Windows Command Shell).
- **Procedures:** The exact in-the-wild execution details used by threat actors (APT29, FIN7).
