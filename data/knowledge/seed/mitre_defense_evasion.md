---
title: "MITRE ATT&CK Defense Evasion (TA0005) TTPs"
tags: ["mitre", "defense-evasion", "t1562", "t1027", "amsi", "obfuscation"]
source: "MITRE ATT&CK TA0005"
---

# MITRE ATT&CK Defense Evasion (TA0005) TTPs
## Source & Authority
MITRE ATT&CK Tactic TA0005 (Defense Evasion).

## Prominent Techniques
- **T1562.001 (Impair Defenses: Disable Tools):** Tampering with EDR agents, modifying Defender exclusions, or patching AMSI (`AmsiScanBuffer`) in memory.
- **T1027 (Obfuscated Files or Information):** Packing, dynamic string decryption, and dead code insertion to bypass static antivirus signatures.
- **T1070.001 (Indicator Removal: Clear Windows Event Logs):** `wevtutil cl Security` or `Clear-EventLog`. Triggers Event ID 1102.
