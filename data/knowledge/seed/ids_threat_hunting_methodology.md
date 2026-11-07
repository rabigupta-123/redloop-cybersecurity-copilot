---
title: "Hypothesis-Driven Threat Hunting Methodology"
tags: ["threat-hunting", "soc", "mitre", "lolbins", "blue-team"]
source: "MITRE ATT&CK / SANS Threat Hunting Summit"
---

# Hypothesis-Driven Threat Hunting Methodology
## Source & Authority
MITRE ATT&CK Framework; SANS Threat Hunting Summit Principles.

## Threat Hunting Lifecycle
1. **Hypothesis Formulation:** Formulate targeted questions based on threat intelligence: "Are adversaries abusing `certutil.exe` to download secondary payloads to endpoints?"
2. **Data Collection & Tooling:** Query process execution telemetry (Sysmon Event ID 1, EDR) across all endpoints.
3. **Pattern Analysis & Stacking:** Perform frequency analysis (long-tail analysis) of command lines, parent-child hierarchies, and outbound destination IPs. Outliers with count = 1 or 2 often represent malicious activity.
4. **Resolution & Automation:** Transform hunting findings into permanent automated detection rules (Sigma/SIEM alerts).
