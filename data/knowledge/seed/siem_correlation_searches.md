---
title: "SIEM Correlation Searches & Alert Tuning Strategy"
tags: ["siem", "correlation", "soc", "splunk", "elastic", "tuning"]
source: "MITRE D3FEND / SANS SEC555"
---

# SIEM Correlation Searches & Alert Tuning Strategy
## Source & Authority
MITRE D3FEND Threat-Informed Defense; SANS SEC555 SIEM with Tactical Analytics.

## Correlation Strategies
1. **Threshold & Time-Window Aggregations:** E.g., > 10 failed authentications followed by 1 successful logon from the same source IP within a 5-minute sliding window (Brute Force Success).
2. **Cross-Data-Source Correlation:** Correlate an EDR process creation event with an outbound network firewall egress flow to an uncategorized external IP within < 2 seconds.
3. **False Positive Tuning:** Document tuning decisions in a versioned repository. Maintain strict baseline exemptions rather than broadly suppressing detection logic.
