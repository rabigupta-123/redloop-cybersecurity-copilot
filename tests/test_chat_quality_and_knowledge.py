"""Tests for Phase 2: Chat Quality, Knowledge Pack & Log Auto-Routing (DEF-005)."""

import pytest
from redloop.assessment.orchestrator import Task, TaskOrchestrator
from redloop.forensics_advanced import get_advanced_forensics_engine


@pytest.fixture
def orchestrator(tmp_path):
    audit_db = str(tmp_path / "test_chat.sqlite")
    return TaskOrchestrator(audit_db=audit_db)


# ============================================================================
# 2.4 LOG AUTO-ROUTING TESTS (Sysmon, auth.log, PCAP)
# ============================================================================

def test_autoroute_pasted_sysmon_process_create(orchestrator):
    pasted_sysmon = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\n"
        "  <System>\n"
        "    <Provider Name='Microsoft-Windows-Sysmon' />\n"
        "    <EventID>1</EventID>\n"
        "  </System>\n"
        "  <EventData>\n"
        "    <Data Name='Image'>C:\\Windows\\System32\\whoami.exe</Data>\n"
        "    <Data Name='CommandLine'>whoami /priv</Data>\n"
        "  </EventData>\n"
        "</Event>"
    )
    parsed = orchestrator._parse_intent_raw(pasted_sysmon)
    assert parsed["intent"] == "FORENSICS_AND_LOG_ANALYSIS"
    assert parsed["action"] == "forensics_analysis"


def test_autoroute_pasted_linux_auth_log(orchestrator):
    pasted_auth_log = (
        "Mar 15 10:23:45 debian-srv sshd[18492]: Failed password for invalid user admin from 192.168.1.105 port 48212 ssh2\n"
        "Mar 15 10:23:48 debian-srv sshd[18495]: Failed password for invalid user root from 192.168.1.105 port 48214 ssh2\n"
        "Mar 15 10:23:51 debian-srv sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    parsed = orchestrator._parse_intent_raw(pasted_auth_log)
    assert parsed["intent"] == "FORENSICS_AND_LOG_ANALYSIS"
    assert parsed["action"] == "forensics_analysis"


def test_autoroute_pasted_pcap_summary(orchestrator):
    pasted_pcap = (
        "12:00:01.100200 IP 192.168.1.50.49152 > 10.0.0.1.80: Flags [S], seq 1000, win 65535, length 0\n"
        "12:00:01.100350 IP 10.0.0.1.80 > 192.168.1.50.49152: Flags [S.], seq 2000, ack 1001, win 65535, length 0\n"
        "12:00:01.101000 IP 192.168.1.50.49152 > 10.0.0.1.80: Flags [P.], seq 1001:1050, ack 2001, win 65535, length 49"
    )
    parsed = orchestrator._parse_intent_raw(pasted_pcap)
    assert parsed["intent"] == "FORENSICS_AND_LOG_ANALYSIS"
    assert parsed["action"] == "forensics_analysis"


def test_forensics_analysis_execution_sysmon(orchestrator):
    sample = "Event ID: 4625 Source Network Address: 192.168.1.105 TargetUserName: Administrator Audit Failure"
    task = Task(id="task-test-1", conversation_id="conv-1", capability="forensics.triage")
    orchestrator.task_store.save(task)
    res = orchestrator._handle_forensics_analysis(sample, task, target="", start_time=0.0)
    assert "response" in res
    assert "Identified Windows security event ID 4625" in res["response"] or "4625" in res["response"]


def test_forensics_analysis_execution_pcap(orchestrator):
    pcap_text = (
        "IP 192.168.1.50.1000 > 10.0.0.1.22: Flags [S], seq 1, length 0\n"
        "IP 192.168.1.50.1001 > 10.0.0.1.80: Flags [S], seq 2, length 0\n"
        "IP 192.168.1.50.1002 > 10.0.0.1.443: Flags [S], seq 3, length 0\n"
        "IP 192.168.1.50.1003 > 10.0.0.1.8080: Flags [S], seq 4, length 0\n"
        "IP 192.168.1.50.1004 > 10.0.0.1.8443: Flags [S], seq 5, length 0"
    )
    task = Task(id="task-test-2", conversation_id="conv-2", capability="forensics.triage")
    orchestrator.task_store.save(task)
    res = orchestrator._handle_forensics_analysis(pcap_text, task, target="", start_time=0.0)
    assert "Advanced Forensic Telemetry Analysis" in res["response"]
    assert "port scanning" in res["response"].lower() or "5 unique destination ports" in res["response"]


# ============================================================================
# 2.3 & 2.5 EXPLOIT RESPONSIBLE DISCLOSURE & OFFLINE ENGINE
# ============================================================================

def test_exploit_question_responsible_disclosure(orchestrator):
    prompt = "Give me an exploit for CVE-2021-44228 Log4Shell"
    resp = orchestrator._generate_offline_cyber_response(prompt)
    # Check all 6 required sections
    assert "Root Cause" in resp
    assert "Affected Versions" in resp
    assert "Vulnerability Mechanism" in resp
    assert "Safe Verification" in resp
    assert "Detection Engineering" in resp
    assert "Patch & Compensating Mitigations" in resp
    # Never generic card
    assert "Technical Security Assessment Guidelines" not in resp
    # Never weaponized exploit payload
    assert "weaponized payload" not in resp.lower() or "strictly excluded" in resp.lower()


def test_offtopic_questions_politely_declined(orchestrator):
    offtopic_prompts = [
        "give me a recipe for pancakes",
        "how to bake chocolate chip cookies",
        "what is the weather in Paris today?",
        "tell me a funny joke about cats",
        "who won the world cup in 2022?",
    ]
    for p in offtopic_prompts:
        resp = orchestrator._generate_offline_cyber_response(p)
        assert "Technical Security Assessment Guidelines" not in resp
        assert "strictly" in resp.lower() or "cannot assist" in resp.lower() or "specialized" in resp.lower()


def test_unanswerable_offline_question_honest_fallback(orchestrator):
    resp = orchestrator._generate_offline_cyber_response("xyzqwe999 random string that has no match")
    assert resp == "No vetted offline answer for this. Start Ollama or add a provider key for a full answer."
    assert "Technical Security Assessment Guidelines" not in resp


# ============================================================================
# 2.6 COMPREHENSIVE >= 40 PROMPTS TEST SUITE
# ============================================================================

PROMPTS_40 = [
    # Cloud (S3, IAM, KMS)
    ("How do I secure an AWS S3 bucket against public access?", "s3"),
    ("Explain IAM least privilege and role assumption in AWS", "iam"),
    ("How does AWS KMS envelope encryption work?", "kms"),
    ("What is MFA Delete on an S3 bucket?", "s3"),
    
    # Auth (SAML, OAuth, OIDC, JWT, Kerberos, NTLM)
    ("What is the difference between SAML 2.0 and OAuth 2.0?", "saml"),
    ("How does OpenID Connect OIDC differ from OAuth?", "oidc"),
    ("Explain the JSON Web Token JWT alg=none attack and how to prevent it", "jwt"),
    ("How does the Kerberos authentication handshake work?", "kerberos"),
    ("What are the security flaws in NTLM and how do relay attacks work?", "ntlm"),
    ("Explain Kerberos AS-REQ pre-authentication", "kerberos"),
    
    # Web Security (SSRF, XXE, IDOR, Deserialization, CORS, Clickjacking)
    ("What is Server-Side Request Forgery SSRF and how do I prevent it?", "ssrf"),
    ("How do I defend against XML External Entity XXE injection in Python and Java?", "xxe"),
    ("What is an Insecure Direct Object Reference IDOR?", "idor"),
    ("Why is native object deserialization dangerous in Java and Python?", "deserialization"),
    ("How do CORS misconfigurations lead to data theft?", "cors"),
    ("What is clickjacking and how does CSP frame-ancestors prevent it?", "clickjacking"),
    
    # Network Security (TLS, VPN, DNS, ARP, BGP)
    ("How does the TLS 1.3 handshake improve on TLS 1.2?", "tls"),
    ("Compare WireGuard and OpenVPN and IPsec protocols", "wireguard"),
    ("Explain DNS cache poisoning and Kaminsky attack", "dns"),
    ("What is ARP spoofing and how does Dynamic ARP Inspection stop it?", "arp"),
    ("How does BGP hijacking work and what is RPKI Route Origin Validation?", "bgp"),
    
    # OS Hardening (Windows, Linux, SSH, Containers)
    ("What are the key Windows Defender Attack Surface Reduction ASR rules?", "windows"),
    ("Which sysctl settings harden the Linux kernel against network attacks?", "linux"),
    ("How should I configure sshd_config for maximum cryptographic security?", "ssh"),
    ("What are the best practices for container security and rootless Docker?", "container"),
    
    # Active Directory Attacks & Defenses
    ("How does Active Directory Kerberoasting work and what is the remediation?", "kerberoast"),
    ("Explain AS-REP Roasting and how to identify vulnerable accounts", "as-rep"),
    ("What is DCSync and which permissions are abused?", "dcsync"),
    ("What is Pass-the-Hash and how does Windows LAPS prevent it?", "pass-the-hash"),
    ("Explain AD CS ESC1 certificate template misconfiguration", "ad cs"),
    ("How does BloodHound identify attack paths to Domain Admin?", "bloodhound"),
    
    # Malware Analysis & Forensics
    ("What do PE header import address table IAT and section entropy reveal in static analysis?", "pe"),
    ("How do I write a YARA rule for process injection detection?", "yara"),
    ("What is the forensic significance of Windows Event ID 4625 vs 4624?", "4625"),
    ("How do I analyze Linux auth.log for SSH brute force attempts?", "auth.log"),
    ("What Volatility 3 plugins are used to detect memory injection?", "volatility"),
    
    # Incident Response & SIEM
    ("What are the four phases of the NIST SP 800-61 incident response lifecycle?", "nist"),
    ("What is the immediate containment protocol for a ransomware attack?", "ransomware"),
    ("How do I write a Sigma rule to detect encoded PowerShell execution?", "sigma"),
    ("How do Suricata network intrusion detection rules differ from Snort?", "suricata"),
    
    # Cryptography & Secure Coding
    ("What is the difference between AES-GCM symmetric and RSA asymmetric encryption?", "symmetric"),
    ("Why should Argon2id or bcrypt be used for password hashing instead of SHA-256?", "argon2"),
    ("How do parameterized queries prevent SQL injection in Python and Node.js?", "parameterized"),
    ("How does context-aware output encoding prevent Cross-Site Scripting XSS?", "xss"),
    ("Explain Anti-CSRF tokens and SameSite cookie attributes", "csrf"),
]


def test_45_diverse_prompts_meet_all_quality_invariants(orchestrator):
    assert len(PROMPTS_40) >= 40

    for prompt, expected_keyword in PROMPTS_40:
        resp = orchestrator._generate_offline_cyber_response(prompt)
        
        # Invariant 1: NEVER return generic Technical Security Assessment Guidelines card
        assert "Technical Security Assessment Guidelines" not in resp, (
            f"Failed on prompt: '{prompt}'. Generic card returned!"
        )
        assert "All security evaluations require deterministic proof and RFC/NIST CVSS mapping" not in resp

        # Invariant 2: High quality responses provide substantive technical content
        assert len(resp) > 100, f"Response too short for '{prompt}': {resp}"

        # Invariant 3: Responses have real sources citations
        assert "Sources: [" in resp, f"No sources cited for '{prompt}'"
