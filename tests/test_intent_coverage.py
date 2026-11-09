"""Comprehensive coverage suite for orchestrator intent parsing and dispatch.

Ensures that orchestrator routing code (parse_intent, _parse_intent_raw)
achieves >= 85% branch coverage across all operational actions and intents.
"""

from __future__ import annotations

import pytest
from redloop.assessment.orchestrator import TaskOrchestrator


@pytest.fixture
def orchestrator() -> TaskOrchestrator:
    return TaskOrchestrator()


INTENT_BRANCH_PROMPTS = [
    # Tool detection
    ("is nmap installed?", "TOOL_DETECTION"),
    ("which tools are installed on the system?", "TOOL_DETECTION"),
    ("check if nikto is available", "TOOL_DETECTION"),

    # Report generation
    ("generate a comprehensive technical report for asmt-999", "REPORT_GENERATION"),
    ("produce a downloadable pdf audit report for assessment asmt-123", "REPORT_GENERATION"),
    ("export the final compliance and risk summary report for asmt-456", "REPORT_GENERATION"),
    ("create an attack_surface report for assessment asmt-789", "REPORT_GENERATION"),

    # Graph and investigation
    ("show the visual graph representation for investigation inv-101", "GRAPH_AND_INVESTIGATION"),
    ("display all attack surface correlation edges for inv-202", "GRAPH_AND_INVESTIGATION"),
    ("render the cytoscape entity graph for inv-303", "GRAPH_AND_INVESTIGATION"),

    # Follow up
    ("what did we find in our previous investigation?", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"),
    ("summarize the findings from our previous investigation", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"),

    # File metadata
    ("inspect pdf author metadata and creation tool on doc.pdf", "FILE_METADATA_ANALYSIS"),
    ("analyze pe header timestamps and compiler version on test.exe", "FILE_METADATA_ANALYSIS"),
    ("extract ole compound document properties from memo.docx", "FILE_METADATA_ANALYSIS"),
    ("inspect png text and ztxt metadata chunks on screenshot.png", "FILE_METADATA_ANALYSIS"),
    ("analyze elf binary headers for payload.bin", "FILE_METADATA_ANALYSIS"),
    ("extract audio tag metadata and encoder version from recording.wav", "FILE_METADATA_ANALYSIS"),
    ("inspect zip archive headers on bundle.zip", "FILE_METADATA_ANALYSIS"),
    ("examine mach-o load commands on binary_macos", "FILE_METADATA_ANALYSIS"),

    # Terminal output
    ("here is my nmap output: 80/tcp open http", "TERMINAL_OUTPUT_ANALYSIS"),
    ("analyze terminal output 443/tcp open https", "TERMINAL_OUTPUT_ANALYSIS"),

    # Kali command assistance
    ("run command: whoami", "KALI_COMMAND_ASSISTANCE"),
    ("whoami", "KALI_COMMAND_ASSISTANCE"),
    ("uname -a", "KALI_COMMAND_ASSISTANCE"),
    ("how do i configure masscan to scan 1000 pps?", "KALI_COMMAND_ASSISTANCE"),
    ("how do i use ffuf to fuzz parameters?", "KALI_COMMAND_ASSISTANCE"),
    ("explain the tcpdump command to capture dns", "KALI_COMMAND_ASSISTANCE"),
    ("what is the tshark command to filter http?", "KALI_COMMAND_ASSISTANCE"),
    ("how do i run sslscan to check fallback?", "KALI_COMMAND_ASSISTANCE"),
    ("nmap syntax for udp scan", "KALI_COMMAND_ASSISTANCE"),

    # Forensics & log analysis
    ("inspect nginx access logs for directory traversal", "FORENSICS_AND_LOG_ANALYSIS"),
    ("analyze firewall drop logs to reconstruct activity", "FORENSICS_AND_LOG_ANALYSIS"),
    ("parse zeek conn.log to find beaconing", "FORENSICS_AND_LOG_ANALYSIS"),
    ("analyze dns query logs for tunneling", "FORENSICS_AND_LOG_ANALYSIS"),
    ("examine powershell script block logging event 4104", "FORENSICS_AND_LOG_ANALYSIS"),
    ("review cloudtrail audit records for iam changes", "FORENSICS_AND_LOG_ANALYSIS"),
    ("eventid 4625 failed logon forensic triage", "FORENSICS_AND_LOG_ANALYSIS"),

    # CTF & challenge
    ("how do i approach a ret2libc binary exploitation challenge?", "CTF_AND_CHALLENGE_ANALYSIS"),
    ("analyze this audio steganography challenge in lsb", "CTF_AND_CHALLENGE_ANALYSIS"),
    ("analyze this cryptographic ctf problem with common modulus", "CTF_AND_CHALLENGE_ANALYSIS"),
    ("how to extract hidden flag from a pcap?", "CTF_AND_CHALLENGE_ANALYSIS"),
    ("decode base64 string aGVsbG8=", "CTF_AND_CHALLENGE_ANALYSIS"),
    ("rot13 decode this flag{secret}", "CTF_AND_CHALLENGE_ANALYSIS"),

    # Coding & research
    ("write a secure python snippet using hkdf-sha256", "CODING_AND_RESEARCH"),
    ("show me a secure implementation of argon2id in python", "CODING_AND_RESEARCH"),
    ("implement a constant-time byte comparison function in c", "CODING_AND_RESEARCH"),
    ("write a secure sql query using asyncpg in python", "CODING_AND_RESEARCH"),
    ("create a go function to parse untrusted json", "CODING_AND_RESEARCH"),
    ("write a secure deserialization parser in rust using serde", "CODING_AND_RESEARCH"),
    ("implement a token bucket rate limiter in python", "CODING_AND_RESEARCH"),
    ("show how to validate and sanitize svg in python", "CODING_AND_RESEARCH"),
    ("write a secure file upload handler in fastapi", "CODING_AND_RESEARCH"),
    ("construct a secure hmac-sha512 webhook handler in node.js", "CODING_AND_RESEARCH"),

    # Audit verify
    ("verify the cryptographic integrity of the audit ledger", "AUDIT_VERIFY"),
    ("check whether audit log records have experienced tampering", "AUDIT_VERIFY"),
    ("validate the sha-256 merkle checkpoint chain across audit entries", "AUDIT_VERIFY"),
    ("check the tamper-evident audit ledger and verify signatures", "AUDIT_VERIFY"),

    # Lifecycle
    ("pause scan asmt-123", "LIFECYCLE"),
    ("resume assessment asmt-123", "LIFECYCLE"),
    ("stop assessment asmt-123", "LIFECYCLE"),

    # General chat explanations
    ("explain how public key cryptography works", "GENERAL_CHAT"),
    ("what is cross-site request forgery?", "GENERAL_CHAT"),
    ("difference between symlink and hardlink", "GENERAL_CHAT"),
    ("teach me about memory corruption", "GENERAL_CHAT"),
    ("definition of vulnerability, exploit, and threat", "GENERAL_CHAT"),
    ("summarize current ip, domain and email intelligence", "GENERAL_CHAT"),
    ("is this email safe when hibp shows no breaches?", "GENERAL_CHAT"),

    # Authorized Reconnaissance
    ("scan this authorized lab target 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("perform an authorized tcp syn port discovery sweep on 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("conduct authorized banner grabbing against 127.0.0.1 port 8080", "AUTHORIZED_RECONNAISSANCE"),
    ("execute an authorized operating system fingerprinting sweep on 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("execute authorized tls cipher suite enumeration on 127.0.0.1 port 8443", "AUTHORIZED_RECONNAISSANCE"),
    ("nikto scan 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("gobuster scan http://127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("web scan http://127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("api scan http://127.0.0.1/graphql", "AUTHORIZED_RECONNAISSANCE"),
    ("dns scan 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),

    # Vulnerability Assessment
    ("evaluate authorized web endpoint 127.0.0.1 for missing security headers", "VULNERABILITY_ASSESSMENT"),
    ("evaluate whether target 127.0.0.1 allows unauthenticated access", "VULNERABILITY_ASSESSMENT"),
    ("perform an authorized web vulnerability check against 127.0.0.1", "VULNERABILITY_ASSESSMENT"),
    ("run assessment on target 127.0.0.1", "VULNERABILITY_ASSESSMENT"),
    ("assess target 127.0.0.1 comprehensive", "VULNERABILITY_ASSESSMENT"),
    ("assess target 127.0.0.1 quick", "VULNERABILITY_ASSESSMENT"),
    ("assess target 127.0.0.1 deep", "VULNERABILITY_ASSESSMENT"),

    # OSINT
    ("investigate email test@example.com", "OSINT_EMAIL"),
    ("investigate phone +14155552671", "OSINT_PHONE"),
    ("search username octocat", "OSINT_USERNAME"),
    ("check public account existence for username defcon", "OSINT_USERNAME"),
    ("investigate 8.8.8.8", "OSINT_IP"),
    ("gather passive threat reputation for ip 64.6.64.6", "OSINT_IP"),
    ("check whether ip 84.200.69.80 belongs to a vpn", "OSINT_IP"),
    ("investigate example.com", "OSINT_DOMAIN"),
    ("inspect spf and dkim records for domain cloudflare.com", "OSINT_DOMAIN"),
    ("check domain registration age for example.org", "OSINT_DOMAIN"),

    # Clarification
    ("conduct a service discovery sweep on the target", "TARGET_CLARIFICATION_REQUIRED"),
    ("execute an email deliverability and footprint check", "TARGET_CLARIFICATION_REQUIRED"),
    ("initiate an authorized tls cipher suite audit", "TARGET_CLARIFICATION_REQUIRED"),

    # Exploit simulation
    ("simulate exploit against 127.0.0.1", "AUTHORIZED_RECONNAISSANCE"),
    ("simulate attack against 127.0.0.1 ssh", "AUTHORIZED_RECONNAISSANCE"),
    ("simulate poc against 127.0.0.1 tls", "AUTHORIZED_RECONNAISSANCE"),
]


@pytest.mark.parametrize("prompt,expected_intent", INTENT_BRANCH_PROMPTS)
def test_intent_dispatch_branches(orchestrator: TaskOrchestrator, prompt: str, expected_intent: str) -> None:
    res = orchestrator.parse_intent(prompt)
    assert res["intent"] == expected_intent, f"Prompt '{prompt}' classified as {res['intent']}, expected {expected_intent}"


def test_context_queries(orchestrator: TaskOrchestrator) -> None:
    # Context queries
    r1 = orchestrator.parse_intent("explain this finding", context={"type": "finding", "id": "find-001"})
    assert r1["action"] == "explain_finding"

    r2 = orchestrator.parse_intent("explain this evidence", context={"type": "evidence", "id": "evi-001"})
    assert r2["action"] == "explain_evidence"

    r3 = orchestrator.parse_intent("show attack surface", context={"type": "asset", "id": "asset-001"})
    assert r3["action"] == "explain_attack_surface"

