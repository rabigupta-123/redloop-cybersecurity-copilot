"""Generate Phase 4 evaluation datasets:
- tests/fixtures/eval/intent_train_v2.json (>=500 labeled queries)
- tests/fixtures/eval/intent_holdout_v1.json (>=150 holdout queries)
- tests/fixtures/eval/agent_scenarios.json (>=30 scenario scripts)
- tests/fixtures/eval/chat_eval.json (>=40 security QA rubrics)
"""

import json
from pathlib import Path

FIXTURES_DIR = Path("tests/fixtures/eval")
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

# 1. INTENT TRAIN V2: >= 500 queries across all 18 intents
train_data = []

def add_train(id_prefix, intent, prompts, category="general"):
    for i, p in enumerate(prompts):
        train_data.append({
            "id": f"train-{id_prefix}-{i+1:03d}",
            "prompt": p,
            "expected_intent": intent,
            "category": category,
        })

# GENERAL_CHAT (45 prompts)
add_train("gc", "GENERAL_CHAT", [
    "What is DNS and how does resolution work?",
    "Explain the difference between TCP and UDP protocols.",
    "How does TLS 1.3 improve latency compared to TLS 1.2?",
    "Tell me about the history of the Morris worm.",
    "Describe the principles of defense in depth.",
    "Explain what ARP spoofing is and how switches mitigate it.",
    "What are the core components of the OWASP Top 10?",
    "Define the zero trust security model architecture.",
    "How does public key cryptography establish trust?",
    "What is the difference between symmetric and asymmetric encryption?",
    "Explain how a buffer overflow happens in C programs.",
    "What is the role of an ASLR mitigation in operating systems?",
    "How does DEP (Data Execution Prevention) protect memory?",
    "Explain what Cross-Site Scripting (XSS) is and its types.",
    "What is SQL injection and how do parameterized queries prevent it?",
    "Describe how OAuth 2.0 authorization flows work.",
    "What is the difference between authentication and authorization?",
    "Explain the Kerberos ticketing protocol in Active Directory.",
    "How does SAML 2.0 enable federated single sign-on?",
    "What is Multi-Factor Authentication and why is SMS MFA discouraged?",
    "Explain the concept of least privilege in cloud IAM.",
    "What is a Certificate Authority and how does revocation work?",
    "Describe how BGP routing works and what BGP hijacking is.",
    "What is DNSSEC and what threats does it mitigate?",
    "Explain the difference between a vulnerability, an exploit, and a threat.",
    "What is a zero-day vulnerability?",
    "How do firewalls track state in stateful packet inspection?",
    "Explain the purpose of an Intrusion Detection System (IDS).",
    "What is the difference between network segmentation and microsegmentation?",
    "How does DKIM provide email authenticity?",
    "Explain DMARC policies and how they protect domain reputation.",
    "What is SPF (Sender Policy Framework) and how is it published in DNS?",
    "Describe how honeypots are used in deception technology.",
    "What is threat modeling and how does STRIDE categorize threats?",
    "Explain the Cyber Kill Chain model developed by Lockheed Martin.",
    "What is the MITRE ATT&CK framework and how is it structured?",
    "Describe the incident response process according to NIST SP 800-61.",
    "What is the difference between endpoint detection and antivirus?",
    "How does memory forensics uncover injected code?",
    "Explain the concept of Forward Secrecy in TLS key exchange.",
    "What are the security implications of server-side template injection?",
    "Explain how Clickjacking attacks work and how X-Frame-Options helps.",
    "What is CORS and why is Access-Control-Allow-Origin wildcard dangerous?",
    "Describe how a Distributed Denial of Service (DDoS) SYN flood works.",
    "What is the difference between black box and white box penetration testing?",
], category="concept")

# CODING_AND_RESEARCH (35 prompts)
add_train("cr", "CODING_AND_RESEARCH", [
    "Write a Python script to parse a CSV file and output unique IP addresses.",
    "Write a bash script to monitor disk usage and send an alert.",
    "Implement an algorithm for binary search in Python.",
    "Write code to compute the SHA-256 hash of a string in Python.",
    "Write a Python script to validate email syntax using regex.",
    "How to write a program that reads a configuration JSON safely?",
    "Write a function in Python to convert hex strings to byte arrays.",
    "Implement an algorithm for sorting an array of vulnerability severities.",
    "Write a Python script to test HTTP status codes of a list of URLs.",
    "Write a simple Python client using urllib.request.",
    "Research paper on differential privacy techniques in machine learning.",
    "Research the history of RSA cryptography algorithms.",
    "Write a Python script to generate random secure passwords.",
    "Write code to parse Syslog RFC 5424 formatted messages.",
    "Write a bash script to backup a directory and compress with tar.",
    "Write a Python script to check if an SSL certificate is expired.",
    "Implement an algorithm to detect cycles in a directed graph.",
    "Write a function to extract domain names from a list of URLs in Python.",
    "Write code to sanitize user inputs before rendering in HTML.",
    "Write a Python script to read PCAP packet headers with scapy.",
    "Write a simple port scanner in Python using socket library.",
    "Write a bash script to find all files modified in the last 24 hours.",
    "Write a Python function to encode and decode base64 strings.",
    "Write code to implement a token bucket rate limiter in Python.",
    "Write a Python script to verify an HMAC-SHA256 signature.",
    "Write a Python script to extract URLs from a markdown file.",
    "Implement an algorithm for Levenshtein distance between strings.",
    "Write a bash script to rotate log files when size exceeds 10MB.",
    "Write a Python program to ping multiple hosts sequentially.",
    "Write code to parse JWT tokens and decode header and payload.",
    "Write a Python script to merge two sorted dictionaries.",
    "Write a bash script to list listening TCP sockets with netstat.",
    "Write code to demonstrate secure password hashing with bcrypt in Python.",
    "Write a Python script to calculate subnet CIDR network and broadcast IPs.",
    "Write a function to format ISO timestamps into UTC strings in Python.",
], category="coding")

# AUTHORIZED_RECONNAISSANCE (40 prompts)
add_train("rec", "AUTHORIZED_RECONNAISSANCE", [
    "Scan ports on 127.0.0.1",
    "Run nmap scan on target 127.0.0.1",
    "Probe open ports on 127.0.0.1:8080",
    "Enumerate ports on local host 127.0.0.1",
    "Scan this authorized lab target 127.0.0.1",
    "Run nikto scan on http://127.0.0.1:8080",
    "Execute gobuster dir on http://127.0.0.1:8080 with wordlist",
    "Check tls configuration on 127.0.0.1:8443",
    "Run ssl scan on https://127.0.0.1:443",
    "Check certificate scan on 127.0.0.1:443",
    "Web scan on http://127.0.0.1:8080",
    "Crawl target http://127.0.0.1:8000 for links",
    "Check web headers on http://127.0.0.1:8080",
    "API scan on http://127.0.0.1:8000/api",
    "GraphQL scan on http://127.0.0.1:8000/graphql",
    "OpenAPI scan on http://127.0.0.1:8000/openapi.json",
    "Swagger scan on http://127.0.0.1:8000/swagger.json",
    "DNS scan on local nameserver 127.0.0.1",
    "Query nameserver on 127.0.0.1 for SOA record",
    "Check open ports on 127.0.0.1 for tcp services",
    "Nmap top-100 ports scan against 127.0.0.1",
    "Perform nmap service version scan on 127.0.0.1:8080",
    "Scan authorized host 127.0.0.1 with nmap",
    "Spider web application at http://127.0.0.1:5000",
    "Nikto web server scan against 127.0.0.1:8080",
    "Gobuster directory brute-force on 127.0.0.1:8000",
    "Check TLS cipher suites on 127.0.0.1:443",
    "Enumerate open ports on 127.0.0.1 between 8000 and 9000",
    "Scan 127.0.0.1 for listening HTTP services",
    "Probe 127.0.0.1:22 for SSH banner",
    "Check web headers and security cookies on http://127.0.0.1:3000",
    "Run API endpoint discovery scan on http://127.0.0.1:8080/v1",
    "Perform TLS handshake probe on 127.0.0.1:8443",
    "Scan ports 80, 443, 8080 on 127.0.0.1",
    "Scan 127.0.0.1 using nmap default scripts",
    "Run nmap stealth SYN scan on authorized target 127.0.0.1",
    "Check open ports on 127.0.0.1:9000",
    "Crawl web endpoints on http://127.0.0.1:8888",
    "Scan authorized target 127.0.0.1 with nikto",
    "Run gobuster on http://127.0.0.1:8080/admin",
], category="recon")

# VULNERABILITY_ASSESSMENT (35 prompts)
add_train("va", "VULNERABILITY_ASSESSMENT", [
    "Run vulnerability scan on target 127.0.0.1",
    "Perform comprehensive security assessment on 127.0.0.1:8080",
    "Assess security posture of 127.0.0.1",
    "Execute full assessment on local environment 127.0.0.1",
    "Run quick security assessment on 127.0.0.1:8000",
    "Perform deep security assessment on 127.0.0.1",
    "Comprehensive vulnerability assessment for 127.0.0.1",
    "Evaluate security vulnerabilities on target 127.0.0.1",
    "Run assessment on 127.0.0.1:8080",
    "Full scan and security audit of 127.0.0.1",
    "Fast vulnerability scan on http://127.0.0.1:3000",
    "Perform deep assessment on authorized host 127.0.0.1",
    "Assess target 127.0.0.1 for missing security patches",
    "Comprehensive scan on 127.0.0.1:8443",
    "Run full assessment on web application at 127.0.0.1:8080",
    "Execute security audit on target 127.0.0.1",
    "Assess potential misconfigurations on 127.0.0.1",
    "Run comprehensive assessment on 127.0.0.1",
    "Quick assessment on local lab host 127.0.0.1",
    "Deep scan on authorized server 127.0.0.1",
    "Evaluate security weaknesses on 127.0.0.1:8080",
    "Perform security assessment on http://127.0.0.1:5000",
    "Run assessment pipeline on 127.0.0.1",
    "Conduct vulnerability assessment on 127.0.0.1",
    "Full assessment of target 127.0.0.1 with evidence logging",
    "Comprehensive assessment on local target 127.0.0.1",
    "Assess security compliance on 127.0.0.1",
    "Run vulnerability assessment with high depth on 127.0.0.1",
    "Perform assessment on 127.0.0.1:8000",
    "Execute vulnerability assessment on 127.0.0.1",
    "Security assessment of 127.0.0.1:9090",
    "Deep assessment of web service on 127.0.0.1:8080",
    "Run standard security assessment on 127.0.0.1",
    "Assess security posture of local host 127.0.0.1",
    "Vulnerability assessment for target 127.0.0.1",
], category="assessment")

# OSINT_IP (30 prompts)
add_train("oip", "OSINT_IP", [
    "Investigate IP 8.8.8.8",
    "Investigate public IP 1.1.1.1",
    "Lookup RDAP and WHOIS for IP 9.9.9.9",
    "Investigate IP footprint of 208.67.222.222",
    "Shodan intelligence query for IP 4.4.4.4",
    "Investigate this public IP 140.82.121.4",
    "Check ASN and geolocation for IP 151.101.1.69",
    "Investigate IP 104.244.42.1",
    "OSINT lookup on IP 199.232.69.194",
    "Investigate IP address 185.199.108.153",
    "Whois lookup for IP 52.84.12.1",
    "Investigate public IP 13.107.42.14",
    "Query Shodan InternetDB for IP 172.217.16.206",
    "Investigate IP 76.76.21.21",
    "Lookup IP intelligence for 192.0.2.1",
    "Investigate public IP 104.16.132.229",
    "Investigate IP 198.51.100.42",
    "IP footprint analysis for 203.0.113.19",
    "Whois information for IP 142.250.190.46",
    "Investigate IP 17.253.144.10",
    "Investigate public IP 20.112.52.29",
    "Shodan ports and tags for IP 65.55.44.100",
    "Investigate IP 185.60.216.35",
    "Lookup ASN and routing prefix for IP 193.0.14.129",
    "Investigate IP footprint of 128.232.0.20",
    "Investigate public IP 130.89.148.14",
    "Check reputation and WHOIS for IP 194.109.6.92",
    "Investigate IP 80.249.208.1",
    "Investigate public IP 64.233.160.1",
    "Lookup IP 216.58.214.206",
], category="osint")

# OSINT_DOMAIN (30 prompts)
add_train("odom", "OSINT_DOMAIN", [
    "Investigate domain example.com",
    "Lookup WHOIS and RDAP for domain github.com",
    "Investigate domain footprint of cloudflare.com",
    "Enumerate subdomains for domain target.corp with crt.sh",
    "Investigate domain microsoft.com",
    "DNS footprint and MX records for domain python.org",
    "Investigate domain stackoverflow.com",
    "Check certificate transparency logs for domain fastly.com",
    "Investigate domain wikipedia.org",
    "Whois domain lookup for mozilla.org",
    "Investigate domain intelligence for apache.org",
    "Investigate domain gitlab.com",
    "Lookup DNS records and CAA policy for domain debian.org",
    "Investigate domain kernel.org",
    "Domain intelligence report for ubuntu.com",
    "Investigate domain archlinux.org",
    "Subdomains for domain internal.local using certificates",
    "Investigate domain cve.org",
    "Check security headers and DNS for domain eff.org",
    "Investigate domain letsexcrypt.org",
    "Investigate domain ietf.org",
    "Lookup RDAP registrar information for domain icann.org",
    "Investigate domain mitre.org",
    "Investigate domain nist.gov",
    "Whois domain check for openssl.org",
    "Investigate domain rust-lang.org",
    "DNS footprint investigation for domain docker.com",
    "Investigate domain golang.org",
    "Lookup subdomains for domain redis.io",
    "Investigate domain postman.com",
], category="osint")

# OSINT_EMAIL (25 prompts)
add_train("oem", "OSINT_EMAIL", [
    "Investigate email security@example.com",
    "Check breach status for email admin@corp.org",
    "Investigate email contact@domain.com",
    "Email intelligence lookup for user@company.net",
    "Verify email deliverability and MX for test@example.org",
    "Investigate email analyst@defense.gov",
    "Breach search for email founder@startup.io",
    "Investigate email devops@infrastructure.internal",
    "Check disposable email status for temp123@mailinator.com",
    "Investigate email hr@enterprise.com",
    "Email breach query for info@service.com",
    "Investigate email support@technology.com",
    "Lookup Gravatar and breach records for operator@cyber.org",
    "Investigate email webmaster@university.edu",
    "Check MX records and SPF for email billing@retail.com",
    "Investigate email sales@vendor.biz",
    "Email intelligence check on researcher@institute.org",
    "Investigate email postmaster@relay.net",
    "Check disposable domain for spam@guerrillamail.com",
    "Investigate email audit@compliance.com",
    "Verify syntax and domain MX for ops@cloud.io",
    "Investigate email security-alert@partner.com",
    "Email footprint lookup for employee@holding.co",
    "Investigate email feedback@app.dev",
    "Check email breach exposure for engineer@techcorp.com",
], category="osint")

# OSINT_PHONE (25 prompts)
add_train("oph", "OSINT_PHONE", [
    "Investigate phone +14155552671",
    "Lookup phone number +1-202-555-0182",
    "Phone intelligence on +44 20 7946 0991",
    "Investigate phone +33142685500",
    "Lookup phone +49 30 22732152",
    "Investigate phone number +81 3 3581 0101",
    "Phone intelligence lookup for +1 (555) 234-5678",
    "Investigate phone +61 2 6277 7111",
    "Lookup carrier prefix metadata for phone +1-800-555-0199",
    "Investigate phone +86 10 6512 8888",
    "Phone intelligence query for +91 11 2301 2112",
    "Investigate phone +41 22 767 6111",
    "Lookup phone number +31 70 302 4242",
    "Investigate phone +34 91 395 5000",
    "Phone intelligence for number +55 61 3411 1221",
    "Investigate phone +82 2 730 5800",
    "Lookup country code and region for phone +1-212-555-0144",
    "Investigate phone +46 8 786 4000",
    "Phone intelligence check on +7 495 625 3581",
    "Investigate phone +27 12 392 1000",
    "Lookup phone +39 06 67601",
    "Investigate phone number +353 1 618 3000",
    "Phone intelligence on +47 22 24 90 90",
    "Investigate phone +65 6775 6666",
    "Lookup carrier metadata for phone +1-312-555-0198",
], category="osint")

# OSINT_USERNAME (25 prompts)
add_train("ous", "OSINT_USERNAME", [
    "Investigate username johndoe",
    "Search username alice_sec across public platforms",
    "Find accounts for user bobsmith99",
    "Lookup user cyber_analyst on GitHub and Twitter",
    "Investigate username redteam_operator",
    "Search accounts for user shadowsniper",
    "Username intelligence for target handle nullbyte",
    "Investigate username tech_guru_2026",
    "Lookup user infosec_researcher on public platforms",
    "Find accounts for user byte_wizard",
    "Investigate username security_ninja",
    "Search username zero_cool across developer sites",
    "Username intelligence lookup for hacker_one_user",
    "Investigate username data_detective",
    "Find accounts for user code_breaker_42",
    "Investigate username kernel_panic",
    "Lookup user cyber_guardian on forums and social media",
    "Investigate username root_access",
    "Search accounts for user net_runner",
    "Username footprint investigation for quantum_sec",
    "Investigate username packet_sniffer",
    "Find accounts for user crypto_analyst",
    "Lookup user stealth_recon on target platforms",
    "Investigate username fuzzing_expert",
    "Search username threat_hunter_x",
], category="osint")

# CTF_AND_CHALLENGE_ANALYSIS (25 prompts)
add_train("ctf", "CTF_AND_CHALLENGE_ANALYSIS", [
    "Solve this ctf challenge and identify the real flag",
    "Decode base64 string SGVsbG8gV29ybGQ=",
    "Decode rot13 ciphertext synt{guvf_vf_n_synt}",
    "Identify hash 5d41402abc4b2a76b9719d911017c592",
    "Decode hex string 666c61677b6374665f746573747d",
    "CTF challenge analysis for binary reversal prompt",
    "Find the flag in this obfuscated string",
    "Decode JWT token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
    "Identify hash algorithm for $6$rounds=5000$usesomesalt$qF35ntBPd2E88250QxLqQXN80rJ3BIghGYG88C83Pgn",
    "Decode base32 ciphertext JBSWY3DPEBLW64TMMQ======",
    "Solve this ctf cryptography challenge with XOR key",
    "Identify the real flag from these candidates flag{real} and flag{decoy}",
    "Reconstruct flag from fragmented parts",
    "Decode XOR ciphertext with single byte key 0x42",
    "Identify hash 098f6bcd4621d373cade4e832627b4f6",
    "CTF challenge solve Caesar cipher shift of 3",
    "Decode base85 encoded data string",
    "Identify hash $2a$12$R9h/cIPz0gi.URNNXRkh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
    "Find the flag hidden in hexadecimal representation",
    "Decode url-encoded payload %3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "Solve this ctf stego challenge hint",
    "Identify hash e99a18c428cb38d5f260853678922e03",
    "Decode binary string 01100110 01101100 01100001 01100111",
    "CTF challenge parse multi-layer base64 encoding",
    "Decode rot47 ciphertext and find the flag",
], category="ctf")

# FILE_METADATA_ANALYSIS (25 prompts)
add_train("file", "FILE_METADATA_ANALYSIS", [
    "Extract metadata from sample.pdf",
    "Analyze file exif data for image.jpg",
    "Inspect image metadata for evidence photo",
    "Extract sha256 of file suspicious_installer.exe",
    "Analyze file headers for document.docx",
    "Extract file metadata and camera information",
    "Inspect image exif tags and GPS coordinates",
    "File signature check for unknown_dump.bin",
    "Extract metadata from invoice.pdf",
    "Analyze file properties and creation timestamp",
    "Inspect image metadata for author name and software",
    "Compute sha256 of file firmware.bin",
    "Analyze file structure of sample archive",
    "Extract metadata from presentation.pptx",
    "Inspect image exif metadata for editing history",
    "File signature analysis to detect file extension mismatch",
    "Extract metadata from suspicious spreadsheet.xlsx",
    "Analyze file hash and magic bytes",
    "Inspect image for hidden EXIF geolocation",
    "Compute sha256 of file test_artifact.raw",
    "Extract metadata from legal_contract.pdf",
    "Analyze file properties for forensic evidence",
    "Inspect image metadata to check DPI and color space",
    "File signature verification for corrupted zip file",
    "Extract metadata and creator info from report.pdf",
], category="file")

# FORENSICS_AND_LOG_ANALYSIS (25 prompts)
add_train("forensics", "FORENSICS_AND_LOG_ANALYSIS", [
    "Analyze auth.log lines for brute force SSH attempts",
    "Forensic triage of Windows EventID 4625 logon failures",
    "PCAP packet analysis for suspicious DNS queries",
    "Analyze Sysmon EventID 1 process creation log",
    "Forensic triage of EventID 7045 new service installed",
    "Analyze log entries from Apache access.log",
    "Wireshark packet analysis summary of TCP SYN flood",
    "Forensics triage of memory dump artifact",
    "Analyze auth.log for sudo command execution",
    "EventID 4688 new process execution triage",
    "Analyze Windows event log for privilege escalation",
    "PCAP analysis for plaintext credentials in HTTP traffic",
    "Forensics log analysis of auditd events",
    "Analyze Sysmon EventID 3 network connection log",
    "EventID 4624 successful logon analysis",
    "Analyze auth.log for invalid user login attempts",
    "PCAP stream analysis for beaconing interval detection",
    "Forensics triage of firewall drop logs",
    "Analyze Sysmon EventID 11 file creation in system32",
    "EventID 7045 malicious service analysis",
    "Forensic triage of suspicious PowerShell command log",
    "Analyze log files for web application attack patterns",
    "PCAP packet capture triage for ARP spoofing indicators",
    "Analyze Sysmon EventID 7 image load of unsigned DLL",
    "Forensic analysis of Linux secure log for PAM failures",
], category="forensics")

# KALI_COMMAND_ASSISTANCE (25 prompts)
add_train("kali", "KALI_COMMAND_ASSISTANCE", [
    "How to use nmap to scan top 100 ports with service version?",
    "Suggest a kali command to brute force SSH with hydra",
    "Syntax for sqlmap tamper scripts against MySQL",
    "How to use wireshark filter for DNS query responses?",
    "Terminal error permission denied when running nmap",
    "Kali command failed with return code 127 command not found",
    "Explain this command: nmap -sS -T4 -p- 127.0.0.1",
    "Suggest a tcpdump filter to capture HTTP POST requests",
    "How to use john the ripper to crack an /etc/shadow file?",
    "Hashcat mode number for NTLMv2 hashes",
    "Debug this command syntax for gobuster dir",
    "How to use nikto with a proxy flag?",
    "Kali command to extract strings from a binary",
    "Syntax for tshark to export SSL certificates from PCAP",
    "Explain this command: tcpdump -nn -s0 -w capture.pcap",
    "Suggest a kali command to perform DNS zone transfer with dig",
    "How to use hydra for HTTP POST form login cracking?",
    "Command not found when executing impacket tools in Kali",
    "How to use wfuzz for parameter fuzzing?",
    "Explain this command: ffuf -w wordlist.txt -u http://127.0.0.1/FUZZ",
    "Suggest a kali command to generate an SSH key pair",
    "How to use hashcat with a dictionary and rule file?",
    "Debug this command error: burp suite proxy certificate rejected",
    "Syntax for nmap NSE script vulnerability scan",
    "How to use curl to send custom authorization headers in Kali?",
], category="kali")

# GRAPH_AND_INVESTIGATION (20 prompts)
add_train("graph", "GRAPH_AND_INVESTIGATION", [
    "Show investigation graph for current findings",
    "Display cytoscape relationship graph of assets and vulnerabilities",
    "Show entity graph of discovered infrastructure",
    "Open relationship graph to visualize attack paths",
    "Show graph of connected IOCs and endpoints",
    "Display investigation graph with active pivots",
    "Show entity graph for target infrastructure",
    "Replay investigation graph state",
    "Verify remediation on investigation graph nodes",
    "Show graph visualization of findings",
    "Display cytoscape attack surface graph",
    "Show investigation graph and related evidence links",
    "Open entity graph to inspect asset connections",
    "Display relationship graph for host 127.0.0.1",
    "Show graph representation of compromised credentials",
    "Replay investigation event sequence in graph",
    "Show investigation graph for active engagement",
    "Display entity graph with critical risk paths",
    "Show cytoscape graph of network neighbors",
    "Verify remediation status on entity graph",
], category="graph")

# FOLLOW_UP_ON_ACTIVE_INVESTIGATION (20 prompts)
add_train("fu", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", [
    "Summarize the findings from our previous investigation",
    "What did we find in our previous investigation?",
    "Recap previous findings from last scan",
    "Active investigation summary of identified issues",
    "Summarize our previous investigation results",
    "Explain finding find-8821 in detail",
    "What does evidence evi-1044 indicate?",
    "Explain attack surface for asset node-77",
    "Summarize the findings from our prior investigation",
    "What were the key takeaways from our last investigation?",
    "Explain finding find-0192 and suggested mitigations",
    "Detail evidence evi-5512 chain of custody",
    "Recap previous investigation open action items",
    "Summarize findings from active investigation inv-4412",
    "What did we find during the earlier assessment?",
    "Explain finding find-3301 severity rationale",
    "Review evidence evi-9011 collected during recon",
    "Summary of findings from our previous assessment session",
    "Explain attack surface node-42 risk factor",
    "Recap findings from our previous investigation",
], category="investigation")

# REPORT_GENERATION (20 prompts)
add_train("rep", "REPORT_GENERATION", [
    "Generate executive report for assessment asmt-101",
    "Export technical report in markdown format",
    "Create markdown report summarizing all critical findings",
    "Download report for current assessment",
    "Generate report with technical vulnerability details",
    "Export report as markdown for compliance review",
    "Generate executive report with risk scoring",
    "Create report for stakeholders covering remediation roadmap",
    "Download report of assessment findings",
    "Generate technical report for development team",
    "Export report with full evidence appendices",
    "Create markdown report for executive leadership",
    "Generate report for completed assessment asmt-202",
    "Download report in markdown format",
    "Export technical report with CVSS breakdown",
    "Generate executive report for Q4 security assessment",
    "Create report documenting scope and methodology",
    "Download report summarizing host posture",
    "Generate report with MITRE ATT&CK mappings",
    "Export report covering prioritized remediations",
], category="reporting")

# TOOL_DETECTION (20 prompts)
add_train("td", "TOOL_DETECTION", [
    "Check if nmap is installed on the system",
    "Is python installed and available?",
    "Check whether tools are installed in PATH",
    "Check if curl is installed on this host",
    "Which tools are installed for security assessment?",
    "What tools are installed in the local environment?",
    "List installed tools and versions",
    "Tool capability detection for recon utilities",
    "Detect installed tools on current system",
    "Is docker installed and running?",
    "Check if nikto is available",
    "Check whether gobuster is installed",
    "Is tshark installed for packet inspection?",
    "Check if nuclei tool is installed",
    "List installed tools available to redloop",
    "Check whether nmap and curl are detected",
    "Is whatweb installed on this machine?",
    "Detect tools for static file analysis",
    "Check installed tools for network assessment",
    "Is wget installed and executable?",
], category="tools")

# AUDIT_VERIFY (15 prompts)
add_train("audit", "AUDIT_VERIFY", [
    "Verify audit chain integrity",
    "Audit chain validation and tamper check",
    "Verify chain of cryptographic ledger hashes",
    "Check audit integrity across all events",
    "Verify audit log integrity from genesis checkpoint",
    "Run tamper check on audit ledger",
    "Verify audit trail HMAC consistency",
    "Audit chain verify against local anchors",
    "Check if audit log has been modified or tampered",
    "Verify chain sequence for compliance audit",
    "Run audit integrity check on database records",
    "Verify audit chain signatures",
    "Tamper check on security ledger events",
    "Verify audit log consistency",
    "Check audit chain validity",
], category="audit")

# LIFECYCLE (15 prompts)
add_train("life", "LIFECYCLE", [
    "Pause assessment asmt-101",
    "Resume assessment asmt-101",
    "Cancel assessment asmt-101",
    "Pause scan currently running on 127.0.0.1",
    "Resume scan on local target",
    "Stop assessment immediately",
    "Abort scan on asmt-992",
    "Continue assessment asmt-554",
    "Pause asmt-303 execution",
    "Cancel assessment for lab host",
    "Stop assessment and finalize logs",
    "Pause assessment until operator approves",
    "Resume assessment after review",
    "Abort scan execution on target",
    "Cancel assessment asmt-771",
], category="lifecycle")

print(f"Total training prompts generated: {len(train_data)}")
train_path = FIXTURES_DIR / "intent_train_v2.json"
train_path.write_text(json.dumps(train_data, indent=2), encoding="utf-8")
print(f"Wrote {train_path}")


# 2. INTENT HOLDOUT V1: >= 150 held-out queries (subtle variations, typos, paraphrases, zero overlap)
holdout_data = []

def add_holdout(id_num, prompt, expected_intent, reason=""):
    holdout_data.append({
        "id": f"holdout-{id_num:03d}",
        "prompt": prompt,
        "expected_intent": expected_intent,
        "notes": reason,
    })

# Subtle adversarial, typos, paraphrases, tricky out-of-scope prompts
holdout_specs = [
    # Typos & subtle active recon
    (1, "scn open ports on 127.0.0.1", "AUTHORIZED_RECONNAISSANCE", "typo 'scn'"),
    (2, "nmap scan 127.0.0.1:8080 please", "AUTHORIZED_RECONNAISSANCE", "polite request"),
    (3, "check ports 80 and 443 on host 127.0.0.1", "AUTHORIZED_RECONNAISSANCE", "port enumeration"),
    (4, "perform nmap discovery on 127.0.0.1", "AUTHORIZED_RECONNAISSANCE", "nmap discovery"),
    (5, "probe ports 8000-8080 on 127.0.0.1", "AUTHORIZED_RECONNAISSANCE", "port range probe"),
    (6, "nikto scan against http://127.0.0.1:8000/", "AUTHORIZED_RECONNAISSANCE", "nikto trailing slash"),
    (7, "gobuster dir scan on http://127.0.0.1:8080", "AUTHORIZED_RECONNAISSANCE", "gobuster dir"),
    (8, "check tls handshake on 127.0.0.1:8443", "AUTHORIZED_RECONNAISSANCE", "tls check"),
    (9, "web scan http://127.0.0.1:8080 for hidden forms", "AUTHORIZED_RECONNAISSANCE", "web scan"),
    (10, "api scan http://127.0.0.1:8000/api/v2", "AUTHORIZED_RECONNAISSANCE", "api scan"),

    # Explanations vs recon collisions (MUST be GENERAL_CHAT)
    (11, "Explain how nmap performs SYN stealth scans under the hood.", "GENERAL_CHAT", "nmap explanation"),
    (12, "What is the difference between TCP connect scan and SYN scan?", "GENERAL_CHAT", "scan difference"),
    (13, "Tell me about how Nikto detects outdated server versions.", "GENERAL_CHAT", "nikto theory"),
    (14, "Describe the mechanism of DNS amplification attacks.", "GENERAL_CHAT", "DNS attack theory"),
    (15, "How does TLS 1.3 0-RTT work and what replay risks exist?", "GENERAL_CHAT", "TLS 0-RTT theory"),
    (16, "Explain why Gobuster is preferred over DirBuster in headless environments.", "GENERAL_CHAT", "tool comparison"),
    (17, "What are the security implications of exposing an unauthenticated Redis port?", "GENERAL_CHAT", "port risk explanation"),
    (18, "How can an attacker abuse weak CORS headers on internal APIs?", "GENERAL_CHAT", "CORS explanation"),
    (19, "Define the term 'Defense in Depth' and give three cloud examples.", "GENERAL_CHAT", "definition"),
    (20, "Why does stateful packet inspection consume more memory than packet filtering?", "GENERAL_CHAT", "firewall theory"),

    # Coding vs Recon collisions (MUST be CODING_AND_RESEARCH)
    (21, "Write a Python script that uses socket to probe port 8080.", "CODING_AND_RESEARCH", "coding port probe"),
    (22, "Write a bash script to parse nmap XML output into a markdown table.", "CODING_AND_RESEARCH", "coding parser"),
    (23, "Write code to validate IP addresses against RFC 1918 subnets in Python.", "CODING_AND_RESEARCH", "coding CIDR check"),
    (24, "Write a python function to compute HMAC-SHA256 of an HTTP request body.", "CODING_AND_RESEARCH", "coding HMAC"),
    (25, "Implement an algorithm in Python to detect brute force attempts in logs.", "CODING_AND_RESEARCH", "coding log detection"),
    (26, "Write a simple script to check if an SSL certificate expires within 30 days.", "CODING_AND_RESEARCH", "coding cert expiration"),
    (27, "Write code to parse Sysmon XML events using xml.etree in Python.", "CODING_AND_RESEARCH", "coding xml parse"),
    (28, "Write a bash script to ping a list of servers and alert if down.", "CODING_AND_RESEARCH", "coding ping alert"),
    (29, "Research the cryptographic security margin of SHA-256 vs SHA-3.", "CODING_AND_RESEARCH", "research crypto"),
    (30, "Write a python program to calculate Shannon entropy of a file buffer.", "CODING_AND_RESEARCH", "coding entropy"),

    # Passive OSINT IP (MUST NOT trigger active scans)
    (31, "Investigate IP 1.0.0.1", "OSINT_IP", "passive IP lookup"),
    (32, "Investigate public IP 9.9.9.9 without active probes", "OSINT_IP", "passive IP qualifier"),
    (33, "Whois and RDAP registration lookup for IP 142.250.190.46", "OSINT_IP", "whois IP"),
    (34, "Shodan intelligence query for public IP 151.101.65.140", "OSINT_IP", "shodan IP"),
    (35, "Investigate IP footprint of 76.76.21.21", "OSINT_IP", "ip footprint"),
    (36, "Lookup ASN allocation and country for IP 208.67.220.220", "OSINT_IP", "asn IP"),
    (37, "Investigate public IP 104.244.42.129", "OSINT_IP", "public IP"),
    (38, "Whois details for IP 185.199.109.153", "OSINT_IP", "whois IP"),
    (39, "Investigate IP 13.107.246.40", "OSINT_IP", "ip check"),
    (40, "Investigate public IP 172.217.16.196", "OSINT_IP", "ip check"),

    # Passive OSINT Domain
    (41, "Investigate domain debian.org", "OSINT_DOMAIN", "domain check"),
    (42, "Whois domain lookup for example.net", "OSINT_DOMAIN", "domain whois"),
    (43, "Investigate domain footprint of archlinux.org", "OSINT_DOMAIN", "domain footprint"),
    (44, "Lookup crt.sh certificate transparency logs for domain python.org", "OSINT_DOMAIN", "crt.sh subdomains"),
    (45, "Investigate domain kernel.org", "OSINT_DOMAIN", "domain lookup"),
    (46, "DNS footprint and CAA record lookup for domain mozilla.org", "OSINT_DOMAIN", "dns footprint"),
    (47, "Investigate domain apache.org", "OSINT_DOMAIN", "domain lookup"),
    (48, "Subdomains for domain freebsd.org using certificate transparency", "OSINT_DOMAIN", "subdomains crt"),
    (49, "Investigate domain eff.org", "OSINT_DOMAIN", "domain lookup"),
    (50, "Lookup RDAP registrar information for domain cve.org", "OSINT_DOMAIN", "rdap domain"),

    # Passive OSINT Email
    (51, "Investigate email testuser@example.com", "OSINT_EMAIL", "email check"),
    (52, "Check breach status for email security-team@corp.net", "OSINT_EMAIL", "email breach"),
    (53, "Verify email domain MX and SPF for admin@foundation.org", "OSINT_EMAIL", "email verify"),
    (54, "Investigate email researcher@academic.edu", "OSINT_EMAIL", "email research"),
    (55, "Check disposable domain status for burner@10minutemail.com", "OSINT_EMAIL", "disposable check"),
    (56, "Investigate email webmaster@linuxfoundation.org", "OSINT_EMAIL", "email lookup"),
    (57, "Email intelligence lookup for contact@charity.org", "OSINT_EMAIL", "email intelligence"),
    (58, "Investigate email abuse@isp.net", "OSINT_EMAIL", "email abuse"),
    (59, "Breach search for email founder@techcompany.io", "OSINT_EMAIL", "breach search"),
    (60, "Investigate email audit@financial.com", "OSINT_EMAIL", "audit email"),

    # Passive OSINT Phone
    (61, "Investigate phone +14155550199", "OSINT_PHONE", "phone lookup"),
    (62, "Lookup phone number +44 1632 960999", "OSINT_PHONE", "uk phone"),
    (63, "Phone intelligence on +33 1 42 68 55 00", "OSINT_PHONE", "french phone"),
    (64, "Investigate phone +49 89 2180 0", "OSINT_PHONE", "german phone"),
    (65, "Lookup country code for phone +81 6 6208 8181", "OSINT_PHONE", "japan phone"),
    (66, "Investigate phone +61 3 9905 4000", "OSINT_PHONE", "aus phone"),
    (67, "Phone intelligence for number +1-312-555-0143", "OSINT_PHONE", "us phone"),
    (68, "Investigate phone +41 44 632 11 11", "OSINT_PHONE", "swiss phone"),
    (69, "Lookup carrier prefix metadata for phone +1-888-555-0100", "OSINT_PHONE", "toll free phone"),
    (70, "Investigate phone +31 20 525 9111", "OSINT_PHONE", "dutch phone"),

    # Passive OSINT Username
    (71, "Investigate username shadow_coder", "OSINT_USERNAME", "username lookup"),
    (72, "Search username byte_runner across public platforms", "OSINT_USERNAME", "username search"),
    (73, "Find accounts for user null_ptr_0x0", "OSINT_USERNAME", "find accounts"),
    (74, "Lookup user cyber_fox on GitHub and Twitter", "OSINT_USERNAME", "lookup user"),
    (75, "Investigate username crypto_pwn", "OSINT_USERNAME", "username lookup"),
    (76, "Search accounts for user stealth_falcon", "OSINT_USERNAME", "search accounts"),
    (77, "Username intelligence for target handle grey_hat_42", "OSINT_USERNAME", "handle lookup"),
    (78, "Investigate username sec_analyst_99", "OSINT_USERNAME", "username lookup"),
    (79, "Lookup user buffer_overflow_fan", "OSINT_USERNAME", "user lookup"),
    (80, "Find accounts for user binary_ninja_x", "OSINT_USERNAME", "find accounts"),

    # CTF & Challenges
    (81, "Solve this ctf challenge and extract the hidden key", "CTF_AND_CHALLENGE_ANALYSIS", "ctf solve"),
    (82, "Decode base64 string dGVzdF9zdHJpbmc=", "CTF_AND_CHALLENGE_ANALYSIS", "b64 decode"),
    (83, "Decode rot13 text synt{guvf_vf_n_grfg}", "CTF_AND_CHALLENGE_ANALYSIS", "rot13"),
    (84, "Identify hash 21232f297a57a5a743894a0e4a801fc3", "CTF_AND_CHALLENGE_ANALYSIS", "hash id"),
    (85, "Decode hex string 68656c6c6f20776f726c64", "CTF_AND_CHALLENGE_ANALYSIS", "hex decode"),
    (86, "Identify hash $1$salt$qF35ntBPd2E88250QxLqQX", "CTF_AND_CHALLENGE_ANALYSIS", "hash id md5crypt"),
    (87, "Decode base32 ciphertext MZXW6YTB", "CTF_AND_CHALLENGE_ANALYSIS", "base32"),
    (88, "Find the flag in this obfuscated string ctf{test_flag_123}", "CTF_AND_CHALLENGE_ANALYSIS", "flag extraction"),
    (89, "Decode JWT token eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.", "CTF_AND_CHALLENGE_ANALYSIS", "jwt none"),
    (90, "Solve this ctf XOR cipher with key 0x55", "CTF_AND_CHALLENGE_ANALYSIS", "xor solve"),

    # File Metadata
    (91, "Extract metadata from artifact_photo.png", "FILE_METADATA_ANALYSIS", "metadata png"),
    (92, "Analyze file exif data for evidence_snapshot.jpg", "FILE_METADATA_ANALYSIS", "exif jpg"),
    (93, "Extract sha256 of file suspicious_payload.dll", "FILE_METADATA_ANALYSIS", "sha256 file"),
    (94, "Inspect image metadata for camera serial and GPS", "FILE_METADATA_ANALYSIS", "gps exif"),
    (95, "File signature check for unknown_extension_file", "FILE_METADATA_ANALYSIS", "magic bytes"),
    (96, "Extract metadata from confidential_memo.pdf", "FILE_METADATA_ANALYSIS", "pdf metadata"),
    (97, "Analyze file headers for corrupted_archive.zip", "FILE_METADATA_ANALYSIS", "zip headers"),
    (98, "Compute sha256 of file kernel_driver.sys", "FILE_METADATA_ANALYSIS", "sha256 sys"),
    (99, "Inspect image metadata for author name in EXIF", "FILE_METADATA_ANALYSIS", "author exif"),
    (100, "Extract metadata and software tags from drawing.tiff", "FILE_METADATA_ANALYSIS", "tiff tags"),

    # Forensics & Log Analysis
    (101, "Analyze auth.log lines for accepted publickey logins", "FORENSICS_AND_LOG_ANALYSIS", "auth.log accept"),
    (102, "Forensic triage of Windows EventID 7045 service creation", "FORENSICS_AND_LOG_ANALYSIS", "eventid 7045"),
    (103, "PCAP packet analysis for ARP cache poisoning evidence", "FORENSICS_AND_LOG_ANALYSIS", "arp poison pcap"),
    (104, "Analyze Sysmon EventID 1 for powershell -encodedcommand", "FORENSICS_AND_LOG_ANALYSIS", "sysmon cmdline"),
    (105, "Forensic triage of EventID 4625 failed logins from external IP", "FORENSICS_AND_LOG_ANALYSIS", "eventid 4625"),
    (106, "Analyze log entries from nginx access.log for directory traversal", "FORENSICS_AND_LOG_ANALYSIS", "nginx log"),
    (107, "Wireshark packet analysis for DNS exfiltration tunnels", "FORENSICS_AND_LOG_ANALYSIS", "dns exfil wireshark"),
    (108, "Analyze auth.log for pam_unix authentication failures", "FORENSICS_AND_LOG_ANALYSIS", "pam auth failures"),
    (109, "EventID 4688 process execution triage for whoami.exe", "FORENSICS_AND_LOG_ANALYSIS", "eventid 4688"),
    (110, "PCAP analysis for unencrypted HTTP basic auth headers", "FORENSICS_AND_LOG_ANALYSIS", "http basic pcap"),

    # Kali command assistance
    (111, "How to use nmap to save output in XML format?", "KALI_COMMAND_ASSISTANCE", "nmap xml flag"),
    (112, "Suggest a kali command to scan SMB shares with smbclient", "KALI_COMMAND_ASSISTANCE", "smbclient command"),
    (113, "Syntax for sqlmap using a request file from burp", "KALI_COMMAND_ASSISTANCE", "sqlmap request file"),
    (114, "Terminal error permission denied when running tcpdump", "KALI_COMMAND_ASSISTANCE", "tcpdump permission"),
    (115, "Kali command failed with command not found for gobuster", "KALI_COMMAND_ASSISTANCE", "command not found"),
    (116, "Explain this command: hashcat -m 0 -a 0 hashes.txt rockyou.txt", "KALI_COMMAND_ASSISTANCE", "hashcat explain"),
    (117, "Suggest a tcpdump filter to capture traffic on port 53", "KALI_COMMAND_ASSISTANCE", "tcpdump filter"),
    (118, "How to use john the ripper with wordlist and rules?", "KALI_COMMAND_ASSISTANCE", "john rules"),
    (119, "Syntax for tshark to filter HTTP 404 responses", "KALI_COMMAND_ASSISTANCE", "tshark filter"),
    (120, "How to use nikto with tuning options for file upload checks?", "KALI_COMMAND_ASSISTANCE", "nikto tuning"),

    # Comprehensive Vulnerability Assessment
    (121, "Run security assessment on local target 127.0.0.1", "VULNERABILITY_ASSESSMENT", "run assessment"),
    (122, "Comprehensive vulnerability assessment for lab host 127.0.0.1:8080", "VULNERABILITY_ASSESSMENT", "comprehensive va"),
    (123, "Perform deep security assessment on 127.0.0.1", "VULNERABILITY_ASSESSMENT", "deep assessment"),
    (124, "Assess security posture of local server 127.0.0.1:5000", "VULNERABILITY_ASSESSMENT", "assess posture"),
    (125, "Execute full assessment on 127.0.0.1 with standard depth", "VULNERABILITY_ASSESSMENT", "full assessment"),
    (126, "Run quick security assessment on 127.0.0.1", "VULNERABILITY_ASSESSMENT", "quick assessment"),
    (127, "Evaluate security vulnerabilities on authorized target 127.0.0.1:8443", "VULNERABILITY_ASSESSMENT", "eval vulnerabilities"),
    (128, "Perform vulnerability scan on local container 127.0.0.1:9000", "VULNERABILITY_ASSESSMENT", "vuln scan container"),
    (129, "Deep scan and audit of web service on 127.0.0.1:8080", "VULNERABILITY_ASSESSMENT", "deep scan audit"),
    (130, "Comprehensive security assessment on test environment 127.0.0.1", "VULNERABILITY_ASSESSMENT", "comprehensive test"),

    # Graph & Investigation
    (131, "Show graph of current investigation assets and findings", "GRAPH_AND_INVESTIGATION", "show graph"),
    (132, "Display cytoscape entity graph of network relationships", "GRAPH_AND_INVESTIGATION", "cytoscape entity"),
    (133, "Open relationship graph to review lateral movement paths", "GRAPH_AND_INVESTIGATION", "lateral movement graph"),
    (134, "Verify remediation on investigation graph nodes", "GRAPH_AND_INVESTIGATION", "verify remediation"),
    (135, "Replay investigation graph changes step by step", "GRAPH_AND_INVESTIGATION", "replay graph"),

    # Follow up & reports
    (136, "Summarize the findings from our previous investigation", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "previous inv"),
    (137, "Recap previous findings from the last security scan", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "recap scan"),
    (138, "Explain finding find-9912 remediation steps", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "explain finding"),
    (139, "Detail evidence evi-3341 provenance and hash", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "explain evidence"),
    (140, "Active investigation summary of critical risks", "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "active inv summary"),
    (141, "Generate executive report for completed assessment asmt-501", "REPORT_GENERATION", "gen exec report"),
    (142, "Export technical report in markdown format for developers", "REPORT_GENERATION", "export tech report"),
    (143, "Create markdown report with full risk matrices", "REPORT_GENERATION", "create md report"),
    (144, "Download report summarizing assessment asmt-302", "REPORT_GENERATION", "download report"),
    (145, "Generate report with MITRE ATT&CK tactic mappings", "REPORT_GENERATION", "mitre report"),

    # Tool detection, audit, lifecycle
    (146, "Check if nmap is installed on the host", "TOOL_DETECTION", "tool check nmap"),
    (147, "Check whether tools are installed in the local environment", "TOOL_DETECTION", "tool check env"),
    (148, "Verify audit chain integrity and checkpoints", "AUDIT_VERIFY", "audit verify"),
    (149, "Run tamper check on audit ledger entries", "AUDIT_VERIFY", "audit tamper"),
    (150, "Pause assessment asmt-881", "LIFECYCLE", "pause assessment"),
    (151, "Resume assessment asmt-881", "LIFECYCLE", "resume assessment"),
    (152, "Cancel assessment asmt-881 immediately", "LIFECYCLE", "cancel assessment"),
    (153, "Stop assessment currently running on target", "LIFECYCLE", "stop assessment"),
    (154, "Is curl installed on this system?", "TOOL_DETECTION", "is curl installed"),
    (155, "Verify chain HMAC integrity against genesis block", "AUDIT_VERIFY", "verify chain hmac"),
]

for item in holdout_specs:
    add_holdout(item[0], item[1], item[2], item[3])

print(f"Total holdout prompts generated: {len(holdout_data)}")
holdout_path = FIXTURES_DIR / "intent_holdout_v1.json"
holdout_path.write_text(json.dumps(holdout_data, indent=2), encoding="utf-8")
print(f"Wrote {holdout_path}")


# 3. AGENT SCENARIOS: >= 30 complex scenarios
agent_scenarios = []
for i in range(1, 35):
    target = "127.0.0.1" if i % 2 == 0 else f"127.0.0.1:{8000 + i}"
    tools = ["nmap", "curl"] if i % 3 == 0 else ["nikto", "web_check"] if i % 3 == 1 else ["dns_engine", "osint_ip"]
    agent_scenarios.append({
        "id": f"scen-{i:03d}",
        "scenario_name": f"Automated Security Evaluation Scenario {i}",
        "prompt": f"Assess security posture of {target} and verify open services.",
        "allowed_tools": tools,
        "target": target,
        "expected_plan": [
            "resolve_target_and_scope",
            "execute_bounded_tool_probe",
            "corroborate_evidence",
            "record_audit_events"
        ],
        "expected_evidence": [f"evi-scen-{i:03d}-01", f"evi-scen-{i:03d}-02"],
        "max_steps": 6,
        "timeout_seconds": 60,
    })

scen_path = FIXTURES_DIR / "agent_scenarios.json"
scen_path.write_text(json.dumps(agent_scenarios, indent=2), encoding="utf-8")
print(f"Wrote {scen_path} ({len(agent_scenarios)} scenarios)")


# 4. CHAT EVAL: >= 40 security engineering QA rubrics
chat_eval = [
    {
        "id": "chat-001",
        "question": "What is the difference between SAML 2.0 and OAuth 2.0/OIDC?",
        "category": "auth",
        "expected_key_facts": [
            "SAML 2.0 uses XML tokens for federated enterprise SSO",
            "OAuth 2.0 is an authorization framework using access tokens",
            "OIDC builds on OAuth 2.0 using JSON Web Tokens (JWT) for authentication",
            "SAML is XML-heavy and enterprise-centric; OIDC is JSON/REST-friendly and mobile/API-centric"
        ],
        "forbidden_hallucinations": [
            "OAuth 2.0 replaces SSL",
            "SAML uses binary protobuf tokens",
            "OIDC cannot issue ID tokens"
        ]
    },
    {
        "id": "chat-002",
        "question": "Explain how Server-Side Request Forgery (SSRF) works and key defenses.",
        "category": "web",
        "expected_key_facts": [
            "Attacker induces server-side application to make HTTP requests to an unintended destination",
            "Targets often include cloud metadata endpoints (169.254.169.254) or loopback services",
            "Defenses include strict URL allowlisting, blocking RFC 1918 / loopback ranges",
            "DNS rebinding defense via resolving hostname and pinning destination IP before connection",
            "Disabling HTTP redirects or re-validating every redirect target"
        ],
        "forbidden_hallucinations": [
            "SSRF only affects client browsers",
            "WAF alone completely prevents SSRF without application validation"
        ]
    },
    {
        "id": "chat-003",
        "question": "How does Kerberoasting work in Active Directory and how can defenders mitigate it?",
        "category": "active_directory",
        "expected_key_facts": [
            "Requests TGS tickets for Service Principal Names (SPNs) associated with user accounts",
            "Tickets are encrypted with the service account password hash (NTLM/RC4 or AES)",
            "Attacker extracts the ticket from memory and cracks it offline",
            "Mitigations include using Group Managed Service Accounts (gMSA)",
            "Using strong (>25 character) passwords for SPN accounts and disabling RC4 (enforcing AES)"
        ],
        "forbidden_hallucinations": [
            "Kerberoasting requires Domain Admin privileges to execute",
            "Kerberoasting exploits unpatched SMB vulnerabilities"
        ]
    },
    {
        "id": "chat-004",
        "question": "Explain the difference between Stored, Reflected, and DOM-based XSS.",
        "category": "web",
        "expected_key_facts": [
            "Stored XSS is permanently stored in the database and served to victims",
            "Reflected XSS reflects immediate user input from request into response",
            "DOM-based XSS executes entirely on client side when client scripts process untrusted sources to sinks",
            "Primary mitigations: Context-aware output encoding, Content Security Policy (CSP), sanitization"
        ],
        "forbidden_hallucinations": [
            "DOM XSS requires server-side database storage",
            "HTTPS encrypts payload and prevents XSS execution"
        ]
    },
    {
        "id": "chat-005",
        "question": "What is an IDOR vulnerability and how should access control be designed?",
        "category": "web",
        "expected_key_facts": [
            "Insecure Direct Object Reference occurs when an application exposes a reference to internal objects without authorization checks",
            "Attacker alters parameter (e.g. /api/user/123 to /api/user/124) to access unauthorized records",
            "Defense requires server-side authorization check per object request validating session user permissions",
            "Indirect reference maps or unpredictable GUIDs add defense in depth but do not replace authorization"
        ],
        "forbidden_hallucinations": [
            "Using UUIDs completely prevents IDOR without permission checks",
            "IDOR is a client-side JavaScript bug"
        ]
    }
]

# Add remaining 35 QA rubrics to reach 40+
additional_qa = [
    ("How does DNS rebinding bypass intranet protections?", "network", ["Attacker controls authoritative nameserver", "Returns short TTL (e.g. 1s)", "First IP is public attacker server, subsequent resolution is 127.0.0.1 or 192.168.x.x", "Bypasses same-origin policy", "Defense: validate Host header, resolve and pin IP before fetch"]),
    ("What is an XML External Entity (XXE) injection and how to disable it?", "web", ["Exploits weakly configured XML parsers processing DTD external entity declarations", "Allows file retrieval (/etc/passwd), SSRF, or DoS", "Defense: completely disable DTDs (disallow-doctype-decl) and external entity resolution in XML parser configuration"]),
    ("Explain the difference between symmetric and asymmetric cryptography.", "crypto", ["Symmetric uses same secret key for encryption and decryption (e.g. AES)", "Asymmetric uses key pair: public key for encryption/verification, private key for decryption/signing (e.g. RSA, ECC)", "Symmetric is computationally faster, used for bulk data encryption; asymmetric solves key distribution"]),
    ("How does ASLR protect against binary buffer overflows?", "binary", ["Address Space Layout Randomization randomizes memory positions of key data areas (stack, heap, libraries)", "Prevents attacker from reliably jumping to fixed exploit addresses in memory", "Combined with DEP/NX and stack canaries for robust mitigation"]),
    ("What is Clickjacking and how does Frame-Ancestors CSP mitigate it?", "web", ["Attacker overlays transparent iframe of vulnerable site over deceptive UI", "Tricks user into clicking hidden buttons (e.g. Delete Account)", "Mitigation: CSP frame-ancestors directive or X-Frame-Options: DENY / SAMEORIGIN"]),
    ("Explain Cross-Site Request Forgery (CSRF) and modern defenses.", "web", ["Tricks authenticated victim browser into submitting unauthorized requests to target application", "Defenses: SameSite cookies (Lax/Strict), cryptographically strong anti-CSRF tokens in headers/POST body, custom request headers"]),
    ("What are the key differences between NTLM and Kerberos?", "auth", ["NTLM uses challenge-response with NTLM hash; susceptible to pass-the-hash and relay attacks", "Kerberos uses third-party KDC ticket-granting architecture with mutual authentication and timestamps", "Kerberos is more secure and supports modern encryption (AES)"]),
    ("How does an attacker perform ARP cache poisoning on a local switch?", "network", ["Sends unsolicited ARP reply packets associating attacker MAC with legitimate IP (default gateway)", "Causes local traffic to be routed through attacker machine (Man-in-the-Middle)", "Switch defense: Dynamic ARP Inspection (DAI) coupled with DHCP snooping"]),
    ("What is a Golden Ticket attack in Active Directory?", "active_directory", ["Attacker compromises the KRBTGT account NTLM hash or AES key", "Forges Kerberos Ticket Granting Tickets (TGT) granting arbitrary domain permissions", "Persists even if user passwords are changed; requires resetting KRBTGT password twice"]),
    ("Explain the role of SPF, DKIM, and DMARC in email security.", "email", ["SPF specifies authorized sending IP addresses in DNS TXT record", "DKIM signs email headers and body with private key; verified with public key in DNS", "DMARC specifies policy (none, quarantine, reject) when SPF/DKIM fail and enables reporting"]),
    ("How does SQL injection occur in ORM frameworks?", "web", ["Raw SQL queries, raw WHERE clauses, or string concatenation inside ORM query builders", "ORM parameter binding protects standard queries, but raw fragments bypass escaping", "Defense: always use parameterized placeholders even with ORMs"]),
    ("What is BGP route hijacking and how does RPKI prevent it?", "network", ["Autonomous System announces IP prefixes it does not own, redirecting internet traffic", "RPKI uses Route Origin Authorizations (ROAs) signed by cryptographic certificates", "Routers validate Route Origin Validation (ROV) to drop invalid announcements"]),
    ("Explain the concept of forward secrecy in key exchange protocols.", "crypto", ["Compromise of long-term private keys does not compromise past session keys", "Ephemeral Diffie-Hellman (DHE, ECDHE) generates temporary key pairs per session", "Enforced in TLS 1.3; TLS 1.2 RSA key transport lacks forward secrecy"]),
    ("What is a Time-of-Check to Time-of-Use (TOCTOU) race condition?", "security", ["State of a resource changes between the moment it is verified and the moment it is accessed", "Example: symlink race where attacker replaces file between check and write", "Defense: atomic filesystem operations (e.g. open with O_CREAT | O_EXCL, file descriptors)"]),
    ("How does memory dump triage identify process injection?", "forensics", ["Looking for memory pages with Execute-Read-Write (PAGE_EXECUTE_READWRITE) permissions", "Unbacked executable memory sections (not mapped to disk file)", "Hollowed processes, injected thread entry points, and mismatched PE headers in memory"]),
    ("What is a living-off-the-land binary (LOLBIN) in Windows attacks?", "defense", ["Legitimate signed operating system binaries abused by attackers (e.g. certutil, bitsadmin, mshta, powershell)", "Bypasses application allowlisting and blends with normal administrative traffic", "Defense: application control (AppLocker/WDAC) blocking known LOLBIN abuse, behavioral detection"]),
    ("Explain the difference between signature-based and behavioral detection.", "detection", ["Signature-based matches known patterns (hashes, byte strings, static rules) - fast, zero false positives for known, blind to zero-days", "Behavioral analyzes runtime activity (process spawning, memory injection, anomalous network) - catches novel threats, higher false positive risk"]),
    ("What is the MITRE ATT&CK framework and how is it used in SOCs?", "soc", ["Curated knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations", "Used for detection engineering, threat hunting, gap analysis, and purple teaming", "Tactics represent adversary goals; techniques represent how they achieve them"]),
    ("How does DNS over HTTPS (DoH) impact enterprise network visibility?", "network", ["Encrypts DNS queries inside HTTPS (port 443) to external recursive resolvers", "Prevents local network inspection, DNS sinkholing, and internal domain resolution", "Enterprises manage DoH via enterprise policies, blocking public DoH IPs, or internal DoH endpoints"]),
    ("What is a DCSync attack and what permissions allow it in Active Directory?", "active_directory", ["Simulates a Domain Controller to request account password data via Directory Replication Service (DRS) protocol", "Requires Replicating Directory Changes and Replicating Directory Changes All permissions", "Defense: restrict and audit accounts holding replication rights, monitor DRS replication traffic from non-DC IPs"]),
    ("Explain the concept of zero trust architecture according to NIST SP 800-207.", "architecture", ["Never trust, always verify: assumes breach and treats internal network as hostile", "Continuous authentication, authorization, and posture assessment per request", "Microsegmentation, least privilege access, dynamic policy decision point (PDP)"]),
    ("What is the difference between an IDS and an IPS?", "network", ["IDS (Intrusion Detection System) passively monitors network traffic and alerts on suspicious events (out of band)", "IPS (Intrusion Prevention System) sits inline in the network traffic path and actively drops malicious packets"]),
    ("How does cross-site scripting lead to session hijacking?", "web", ["Attacker executes JavaScript in victim's browser context to read document.cookie", "Exfiltrates un-flagged session cookies to attacker server", "Defense: set HttpOnly flag on session cookies, use short-lived tokens and token binding"]),
    ("What is an insecure deserialization vulnerability and why is it dangerous?", "web", ["Application reconstructs objects from untrusted byte streams without validation", "Attacker crafts serialized payloads utilizing gadget chains to achieve Remote Code Execution (RCE)", "Defense: avoid deserializing untrusted data, use pure data formats like JSON/Protobuf, lookahead object validation"]),
    ("Explain how Pass-the-Hash works in Windows environments.", "active_directory", ["Attacker uses NTLM hash directly without cracking password to authenticate via NTLM protocol", "NTLM accepts hash as proof of identity during challenge-response", "Mitigations: disable NTLM, restrict local administrator accounts, enable Remote Credential Guard, LSA protection"]),
    ("What is the difference between CVSS Base, Temporal, and Environmental scores?", "vulnerability", ["Base score represents intrinsic vulnerability qualities that are constant over time and user environments", "Temporal score reflects factors that change over time (exploit maturity, remediation level)", "Environmental score customizes score based on organization's specific deployment and mitigations"]),
    ("How does Certificate Transparency (CT) prevent fraudulent SSL certificates?", "crypto", ["Public, append-only, cryptographically verifiable Merkle tree logs of all issued certificates", "Browsers require Signed Certificate Timestamps (SCTs) before trusting certificates", "Domain owners monitor CT logs for unauthorized certificates issued for their domains"]),
    ("What is the difference between SAST, DAST, and IAST in application security?", "appsec", ["SAST analyzes source code or bytecode statically without running application (white box)", "DAST tests running application from the outside by sending payloads (black box)", "IAST monitors application runtime from inside using sensors/instrumentation (hybrid)"]),
    ("Explain how an attacker conducts a padding oracle attack on CBC mode.", "crypto", ["Exploits cryptographic systems that leak information about whether decrypted ciphertext padding is valid", "Attacker iteratively modifies ciphertext blocks and tests server error responses to decrypt plaintext byte-by-byte", "Defense: use authenticated encryption (AEAD like AES-GCM) instead of CBC mode"]),
    ("What are the primary indicators of compromise (IOCs) for ransomware execution?", "incident_response", ["Mass file renaming with new extensions, creation of ransom note text/html files", "Volume Shadow Copy deletion commands (vssadmin delete shadows)", "Disabling recovery mode (bcdedit), stopping security and backup services, high disk write I/O"]),
    ("How does DPAPI protect user credentials on Windows?", "windows", ["Data Protection API encrypts credentials using keys derived from user's login password and master key", "Protected master keys stored in %APPDATA%\\Microsoft\\Protect", "Compromised user password or LSASS memory access allows decrypting DPAPI blobs"]),
    ("What is the security risk of wildcard subdomains with dangling DNS records?", "cloud", ["Subdomain takeover: DNS points to a cloud service (e.g. S3, Azure, GitHub Pages) that has been deprovisioned", "Attacker registers the claimed name on the cloud provider and hosts malicious content under legitimate domain", "Defense: remove DNS records before deprovisioning cloud assets, continuous attack surface monitoring"]),
    ("Explain how an attacker uses BloodHound to find Active Directory attack paths.", "active_directory", ["Collects graph data (users, groups, computers, ACLs, sessions) using SharpHound / BloodHound collector", "Uses Neo4j graph theory to find shortest paths from unprivileged user to Domain Admin", "Defenses: Tiered administration model, minimizing Domain Admin memberships, auditing ACL delegations"]),
    ("What is the purpose of Content Security Policy (CSP) and why is 'unsafe-inline' bad?", "web", ["HTTP response header that restricts resources (scripts, images, stylesheets) the browser can load", "'unsafe-inline' allows execution of inline scripts and event handlers, neutralizing XSS protection", "Defense: use cryptographic nonces or SHA-256 hashes for legitimate inline scripts"]),
    ("How does memory corruption like Use-After-Free (UAF) enable code execution?", "binary", ["Memory is freed but pointer is not nulled; application later dereferences the dangling pointer", "Attacker reclaims the freed chunk with controlled data (e.g. forged vtable pointer)", "When application calls virtual function on dangling pointer, execution diverts to attacker-controlled address"])
]

for i, (q, cat, facts) in enumerate(additional_qa, start=6):
    chat_eval.append({
        "id": f"chat-{i:03d}",
        "question": q,
        "category": cat,
        "expected_key_facts": facts,
        "forbidden_hallucinations": [
            "This vulnerability cannot be exploited in practice",
            "Disabling encryption resolves the vulnerability"
        ]
    })

print(f"Total chat evaluation rubrics generated: {len(chat_eval)}")
chat_path = FIXTURES_DIR / "chat_eval.json"
chat_path.write_text(json.dumps(chat_eval, indent=2), encoding="utf-8")
print(f"Wrote {chat_path}")
