# REDLOOP Incident Case Management Guide

**Module:** `src/redloop/assessment/case_management.py`  
**API Endpoints:** `/api/cases`, `/api/cases/{case_id}`, `/api/cases/{case_id}/notes`, `/api/cases/{case_id}/evidence`, `/api/cases/{case_id}/timeline`  

---

## 1. Case Lifecycle & State Graph

REDLOOP supports eight distinct investigation states:

```
  [OPEN] ------------> [INVESTIGATING] ------------> [RESOLVED] ---> [CLOSED]
    |                          |                        ^              |
    |                          +---> [PENDING_APPROVAL] |              v
    |                          |                        |         [REOPENED]
    |                          +---> [CONTAINMENT] -----+              |
    |                          |                        |              |
    |                          +---> [MONITORING] ------+              |
    |                                                                  |
    +------------------------------------------------------------------+
```

### State Machine Rules
- Cases open in `OPEN` state and transition to `INVESTIGATING` once assigned.
- If high-risk actions are proposed, the case can move to `PENDING_APPROVAL`.
- Once containment executes, the case transitions to `CONTAINMENT_IN_PROGRESS` or `MONITORING`.
- Closed cases can be re-opened with `REOPENED`, logging an explicit audit record in `reopen_history`.

---

## 2. API Usage Examples

### 2.1 Create a Case
```bash
curl -X POST http://127.0.0.1:8765/api/cases \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{
    "title": "Active SQLi and PowerShell Execution",
    "description": "Correlated web exploitation targeting web-gateway host.",
    "severity": "HIGH",
    "priority": "P2",
    "assigned_to": "tier1_analyst"
  }'
```

### 2.2 Add an Analyst Note
```bash
curl -X POST http://127.0.0.1:8765/api/cases/case-12345/notes \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{
    "author": "analyst_alice",
    "content": "Verified SQL injection attempt in /var/log/nginx/access.log at 12:00:00Z."
  }'
```

### 2.3 Attach Evidence Ledger Records
```bash
curl -X POST http://127.0.0.1:8765/api/cases/case-12345/evidence \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{
    "evidence_ids": ["evi-nginx-sqli-01", "evi-sysmon-ps-02"]
  }'
```

### 2.4 Transition Case Status
```bash
curl -X PATCH http://127.0.0.1:8765/api/cases/case-12345 \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{
    "status": "RESOLVED",
    "closure_reason": "WAF rule deployed and host quarantined."
  }'
```
