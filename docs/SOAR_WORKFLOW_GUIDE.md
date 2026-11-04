# REDLOOP SOAR Workflow & Execution Guide

**Module:** `src/redloop/assessment/soar_engine.py`  
**API Endpoints:** `/api/soar/workflows`, `/api/soar/executions`  

---

## 1. Workflow Lifecycle & State Machine

Every SOAR workflow execution is managed by a deterministic state transition machine with 11 validated states:

```
  [DRAFT] ---> [VALIDATED] ---> [READY] ---> [RUNNING] ---> [COMPLETED]
                                   |            |
                                   |            +---> [WAITING_FOR_APPROVAL] ---> [RUNNING]
                                   |            |
                                   |            +---> [PAUSED] ---> [RUNNING]
                                   |            |
                                   |            +---> [PARTIAL]
                                   |            |
                                   |            +---> [FAILED] ---> (Retry) ---> [READY]
                                   |            |
                                   +------------+---> [CANCELLED]
                                   |            |
                                   +------------+---> [BLOCKED]
```

### State Definitions
- **`READY`**: Workflow definition validated and queued for execution.
- **`RUNNING`**: Workflow engine actively executing sequential action steps.
- **`WAITING_FOR_APPROVAL`**: Workflow paused awaiting operator capability token authorization for a high-risk containment step.
- **`COMPLETED`**: All steps executed successfully.
- **`PARTIAL`**: Non-critical step skipped or failed; core response completed.
- **`FAILED`**: Critical action failure or unhandled exception.
- **`CANCELLED`**: Execution cancelled by operator.
- **`BLOCKED`**: Execution halted due to security policy or SSRF validation.

---

## 2. Triggering Workflows

Workflows can be initiated automatically by detection alerts or manually by analysts:

### Automated Trigger Example
```python
from redloop.assessment.soar_engine import SOAREngine, TriggerType

engine = SOAREngine.get_instance()
trigger = engine.create_trigger(
    trigger_type=TriggerType.ALERT,
    source_record_id="alt-auth-409",
    target_context="198.51.100.25",
    provenance="SEC-AUTH-001",
)

# Automated execution with deduplication guard
record = engine.execute_workflow("WF-BRUTE-FORCE", trigger)
print("Execution status:", record.state.value)
```

### Deduplication Policy
- Deduplication keys are generated as: $\text{SHA-256}(\text{trigger\_type} \parallel \text{source\_record\_id} \parallel \text{target\_context})$.
- Repeated triggers for the same event and target are blocked by default to prevent cascade loops.
- Analysts can override with `allow_rerun=True`.

---

## 3. Cancelling Running Executions

Executions can be cancelled at any point prior to completion:
```bash
curl -X POST http://127.0.0.1:8765/api/soar/executions/exec-12345/cancel \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{"reason": "False positive test", "operator": "analyst_bob"}'
```
