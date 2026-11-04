# EDR & XDR Integrations Guide (Microsoft Defender & CrowdStrike Falcon)

## Overview

REDLOOP integrates with industry-leading Endpoint Detection and Response (EDR) platforms:
1. **Microsoft Defender for Endpoint (MDE)** via Microsoft Graph / Security Center API.
2. **CrowdStrike Falcon** via Falcon OAuth2 REST API.

---

## 1. Capabilities Supported

### Microsoft Defender for Endpoint:
- `GET_DEVICE_INVENTORY`: Enumerates onboarded endpoints.
- `GET_DEVICE_ALERTS`: Pulls endpoint alerts.
- `ISOLATE_ENDPOINT`: Isolates compromised hosts (Approval-Gated).
- `RELEASE_ENDPOINT`: Releases isolated hosts (Approval-Gated).

### CrowdStrike Falcon:
- `GET_DEVICE_INVENTORY`: Queries Falcon device AID inventory.
- `GET_DEVICE_ALERTS`: Ingests endpoint detections.
- `ISOLATE_ENDPOINT`: Enforces network containment on hosts (Approval-Gated).
- `RELEASE_ENDPOINT`: Removes network containment (Approval-Gated).

---

## 2. Mandatory Approval Gating for Destructive Containment Actions

In accordance with strict security architecture standards:
- Any call to `isolate_endpoint` or `contain_host` without a verified `capability_token` is immediately blocked and returns:
  ```json
  {
    "status": "WAITING_FOR_APPROVAL",
    "details": "High-risk endpoint isolation requires operator capability authorization token."
  }
  ```
- No outbound network traffic or API request is generated until an authorized operator issues an approval capability through the SOAR Playbook Approval Store.
- Capability tokens are single-use and bound to exact operation parameters. Replaying or tampering with tokens is rejected atomically.
