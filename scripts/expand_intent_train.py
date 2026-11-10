"""Expand training examples in tests/fixtures/eval/intent_train_v2.json so all classes have >= 30 items."""
import json
from collections import Counter
from pathlib import Path

train_path = Path("tests/fixtures/eval/intent_train_v2.json")
with open(train_path, "r", encoding="utf-8") as f:
    data = json.load(f)

existing_prompts = {d["prompt"].strip().lower() for d in data}

additions = [
    # AUDIT_VERIFY (18 -> 30, need 12)
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Verify the cryptographic hash chain of the assessment database."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Check the SQLite audit ledger for any broken prev_hash links."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Validate the HMAC signature checkpoint for the security event log."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Audit ledger verification: confirm no rows were altered or deleted."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Run an integrity proof audit across all recent operator actions."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Inspect the audit trail sequence numbers to detect rollback attacks."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Verify external ledger checkpoint file against database table state."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Check if the audit database triggers prevented record tampering."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Produce a cryptographic ledger verification report for compliance."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Verify HMAC-SHA256 signature chain across all recorded events."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Verify audit log integrity and report unanchored tail events."},
    {"expected_intent": "AUDIT_VERIFY", "category": "audit", "prompt": "Check audit ledger checkpoint status and verify rolling hash."},

    # FOLLOW_UP_ON_ACTIVE_INVESTIGATION (24 -> 30, need 6)
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "In the current case, what did we discover on the perimeter host?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Regarding the previous finding, can we pull the associated evidence?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Continue working on the active incident investigation case."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "What are the next recommended steps for this active ticket?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Review the latest findings collected under our open case."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Follow up on the unresolved alerts from the previous scan."},

    # GRAPH_AND_INVESTIGATION (24 -> 30, need 6)
    {"expected_intent": "GRAPH_AND_INVESTIGATION", "category": "graph", "prompt": "Show me the attack graph mapping the compromised web nodes."},
    {"expected_intent": "GRAPH_AND_INVESTIGATION", "category": "graph", "prompt": "Render the topology graph showing lateral movement paths."},
    {"expected_intent": "GRAPH_AND_INVESTIGATION", "category": "graph", "prompt": "Visualize the attack surface attack chain connecting the subdomains."},
    {"expected_intent": "GRAPH_AND_INVESTIGATION", "category": "graph", "prompt": "Display the visual dependency graph for target infrastructure."},
    {"expected_intent": "GRAPH_AND_INVESTIGATION", "category": "graph", "prompt": "Query the attack path graph for highest-risk traversal routes."},
    {"expected_intent": "GRAPH_AND_INVESTIGATION", "category": "graph", "prompt": "Export the entity relationship attack graph in JSON format."},

    # LIFECYCLE (19 -> 30, need 11)
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Shut down the local RedLoop assessment workbench gracefully."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Restart the RedLoop API service and clear ephemeral caches."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Display active process status and uptime for RedLoop services."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Trigger a graceful restart of the local assessment engine."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Check the operational health and readiness of the copilot daemon."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Terminate background tasks and halt the active worker pool."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Reload configuration settings from disk without dropping connections."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Stop the loopback workbench server on port 8765."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Initialize RedLoop system workspace and verify environment status."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Check server uptime, worker thread pool, and daemon status."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Gracefully flush pending transactions and stop the runner."},

    # REPORT_GENERATION (25 -> 30, need 5)
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Export a PDF executive summary report of our pentest findings."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Generate a markdown vulnerability report citing verified evidence hashes."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Compile the complete technical bug-bounty assessment report."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Create an executive security assessment debrief in PDF format."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Build a formal penetration testing report documenting confirmed flaws."},

    # TOOL_DETECTION (23 -> 30, need 7)
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Check which local network scanning utilities are installed on this machine."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Detect installed forensic analysis and packet inspection tools."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Which security binaries are present on the system PATH?"},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Scan system environment to detect installed pentest software versions."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Verify if nmap, sqlmap, gobuster, or sublist3r are installed locally."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Audit available CLI assessment tools and report environment capabilities."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "List available security tools and execution adapters in RedLoop."},
]

added_count = 0
for item in additions:
    p_norm = item["prompt"].strip().lower()
    if p_norm not in existing_prompts:
        item["id"] = f"train-exp-{len(data) + 1:04d}"
        data.append(item)
        existing_prompts.add(p_norm)
        added_count += 1

with open(train_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"Added {added_count} training examples. New total: {len(data)}")
counts = Counter(d["expected_intent"] for d in data)
for intent, count in sorted(counts.items()):
    print(f"  {intent:<35} {count}")

