"""Generate fresh intent_holdout_v4.json with 0 hash and 0 6-gram overlap with (train + v1 + v2 + v3)."""
import json
import re
from pathlib import Path

def tokenize(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text.lower())

def get_ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    return set(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))

# Load all prior datasets: train, v1, v2, v3
train_path = Path("tests/fixtures/eval/intent_train_v2.json")
v1_path = Path("tests/fixtures/eval/intent_holdout_v1.json")
v2_path = Path("tests/fixtures/eval/intent_holdout_v2.json")
v3_path = Path("tests/fixtures/eval/intent_holdout_v3.json")

prior_prompts = []
for p in (train_path, v1_path, v2_path, v3_path):
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            prior_prompts.extend(x["prompt"] for x in data)

prior_prompt_set = {p.strip().lower() for p in prior_prompts}
prior_6grams = set()
for p in prior_prompts:
    toks = tokenize(p)
    prior_6grams.update(get_ngrams(toks, 6))

print(f"Total prior prompts: {len(prior_prompts)}")
print(f"Total prior 6-grams: {len(prior_6grams)}")

# Candidate prompts for Holdout v4: 12 prompts across each of the 17 classes = 204 items
CANDIDATES = [
    # 1. REPORT_GENERATION (12)
    {"prompt": "Deliver an executive briefing portfolio encapsulating vulnerability findings on target 198.51.100.99", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Generate an HTML security audit dossier covering confirmed ingress vectors and exposure ratings", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Output a finalized penetration test writeup in formatted markdown for executive sponsors", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Compile a risk mitigation brief summarizing critical severity deficiencies across scoped web services", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Produce a client-deliverable compliance documentation packet evaluating ISO27001 readiness posture", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Prepare an assessment findings brochure illustrating discovered flaws and suggested remediation steps", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Draft an engagement conclusion summary document reviewing external attack perimeter exposure metrics", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Publish a sanitized technical post-mortem report outlining web exploitation validation findings", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Assemble a PDF executive debrief paper presenting prioritized vulnerability management items", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Export an assessment deliverable ledger summarizing observed weaknesses across production endpoints", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Create an executive debrief pamphlet breaking down penetration testing discoveries and business impacts", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Synthesize security test observations into a comprehensive findings compendium for leadership", "expected_intent": "REPORT_GENERATION"},

    # 2. GRAPH_AND_INVESTIGATION (12)
    {"prompt": "Plot an attack vector traversal chart connecting ingress perimeter nodes with core databases", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Construct a dependency link visualization tracking credential pivot routes across enterprise assets", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Map graph neighborhood relations outwards from infected endpoint workstation-finance-03", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Render an interactive node topology diagram illustrating microservice communication relationships", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Calculate centrality scores across the asset relational graph to pinpoint choke point servers", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Display an attack path visual schema demonstrating multi-stage privilege escalation chains", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Query the relational graph index to identify shortest paths between untrusted web roots and LDAP", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Draw an infrastructure layout network graph highlighting firewall boundary segmentation", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Visualize trust boundary intersections in the identity graph connecting external vendors", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Generate a graph model layout showing blast radius reachability from the DMZ edge gateway", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Diagram lateral movement exposure corridors within the hybrid cloud infrastructure model", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Extract the shortest adversary transition pathway through intermediate jump boxes to storage", "expected_intent": "GRAPH_AND_INVESTIGATION"},

    # 3. KALI_COMMAND_ASSISTANCE (12)
    {"prompt": "Which command line arguments enable multi-threaded dictionary brute-forcing in ffuf?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Explain syntax conventions when setting up pivoting relays using socat on Linux systems", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Provide the exact command parameters to dump Kerberos tickets using impacket ticketer", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "How do I configure hydra to avoid account lockouts while testing SMTP credentials?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "What flags instruct masscan to inspect banner outputs without crashing router devices?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Show terminal parameters for capturing raw beacon frames using airmon-ng and airodump-ng", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Demonstrate the proper CLI options for invoking crackmapexec against winrm services", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "How to executeResponder in analysis mode without answering poisonous LLMNR queries?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "What parameters should be provided to sqlmap for extracting tables via time-based blind injection?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Explain CLI usage patterns for automating nikto vulnerability audits over secure socks proxies", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Provide guidance on invoking bloodhound-python with LDAPS authentication and custom collection loops", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Which arguments allow john the ripper to apply custom word mangling mutation rules?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},

    # 4. FORENSICS_AND_LOG_ANALYSIS (12)
    {"prompt": "Examine the Windows event viewer records for abnormal account creations under Event ID 4720", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Review this snippet of apache error_log to identify directory traversal exploitation attempts", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Inspect the captured memory artifact for signs of process hollowing in svchost.exe", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Triage these Sysmon telemetry entries matching Event 7 image load anomalies in rundll32", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Analyze Linux auditd logs for unauthorized privilege modification via sudoers file edits", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Inspect zeek ssl.log outputs to detect anomalous self-signed server certificate handshakes", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Investigate this packet capture trace for indicators of DNS tunneling command and control", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Scan authentication journal messages in auth.log for successful SSH logins from external subnets", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Evaluate CloudTrail management events indicating unauthorized IAM policy modifications", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Review Suricata fast.log alerts flagging outbound Cobalt Strike malleable C2 profiles", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Parse these raw nginx reverse proxy logs to isolate automated SQL injection probe traffic", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Assess firewall connection tracking dumps for high-volume data staging prior to exfiltration", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},

    # 5. OSINT_IP (12)
    {"prompt": "Look up geolocation records, ISP ownership, and route announcements for IP 198.51.100.88", "expected_intent": "OSINT_IP"},
    {"prompt": "Check threat intelligence reputation and honeypot trigger counts for public address 203.0.113.72", "expected_intent": "OSINT_IP"},
    {"prompt": "Query IP reputation databases for host 192.0.2.145 to evaluate abuse complaint frequency", "expected_intent": "OSINT_IP"},
    {"prompt": "Investigate routing prefix allocation and ASN ownership details for external IP 198.51.100.210", "expected_intent": "OSINT_IP"},
    {"prompt": "Retrieve passive reputation data and historical malicious score for address 203.0.113.19", "expected_intent": "OSINT_IP"},
    {"prompt": "Check if IP address 192.0.2.77 has been recorded in active botnet command node listings", "expected_intent": "OSINT_IP"},
    {"prompt": "Lookup autonomous system number and BGP origin history for host address 198.51.100.4", "expected_intent": "OSINT_IP"},
    {"prompt": "Gather open-source threat intelligence intelligence relating to external IPv4 node 203.0.113.111", "expected_intent": "OSINT_IP"},
    {"prompt": "Query pDNS historical repositories to identify domain names that previously resolved to 192.0.2.233", "expected_intent": "OSINT_IP"},
    {"prompt": "Query Shodan and Censys telemetry records for public facing IP 198.51.100.60", "expected_intent": "OSINT_IP"},
    {"prompt": "Check IP abuse database registries to determine if 203.0.113.84 is an active Tor exit relay", "expected_intent": "OSINT_IP"},
    {"prompt": "Retrieve registrar registry block assignments and country code data for address 192.0.2.18", "expected_intent": "OSINT_IP"},

    # 6. OSINT_DOMAIN (12)
    {"prompt": "Gather whois records, registrar identity, and expiration timestamps for domain nebula-ops.org", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Inspect certificate transparency logs on crt.sh to uncover subdomains for staging-vault.net", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Analyze DNS mail exchange MX records and SPF validation configurations for domain apex-defense.io", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Query passive DNS caches to map past hosting IP changes for portal.target-corp.com", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Check domain reputation score and phishing threat flags for apex-fintech-systems.com", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Enumerate exposed nameservers and DNSSEC signing parameters for enterprise-domain.co.uk", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Investigate historical WHOIS registrant contacts and nameserver records for cloud-infra.org", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Audit DKIM, DMARC policy enforcement, and TXT verification entries for mail.corp-internal.com", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Discover virtual hosts and SSL certificate subject alternative names for gateway.edge-sec.net", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Check security headers, HSTS preloading, and TLS ciphers for payment-portal.example.org", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Perform passive reconnaissance on domain registration metadata for global-logistics-hub.biz", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Look up reverse DNS pointers and sub-delegated zone records for auth.services-platform.net", "expected_intent": "OSINT_DOMAIN"},

    # 7. OSINT_EMAIL (12)
    {"prompt": "Verify mailbox existence and MX delivery route for address devops-lead@secure-banking.net", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Check if email account security-architect@fin-exchange.org appeared in public breach dumps", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Query breach databases to check compromise status for cto-office@cloud-operations.io", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Inspect email handle admin-monitoring@health-analytics.com for associated social profiles", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Validate SMTP recipient deliverability and catch-all status for auditor@compliance-audit.org", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Search credential spill records to verify compromised passwords for developer7@staging-app.net", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Investigate email address sysadmin-core@internal-platform.biz for open source mentions", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Check HaveIBeenPwned API entries for enterprise address lead-engineer@defense-systems.com", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Audit deliverability and disposable mailbox domain status for contact@temp-inbox-mail.org", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Determine if email address infrastructure-team@global-network.co has leaked credentials", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Look up public PGP keyrings and code commit logs for author dev-maintainer@crypto-open.io", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Gather breach exposure intelligence regarding corporate email ceo-desk@enterprise-holdings.com", "expected_intent": "OSINT_EMAIL"},

    # 8. OSINT_USERNAME (12)
    {"prompt": "Locate public accounts registered across social platforms for handle ghost_recon_99", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Search developer code hosting repositories and paste services for alias cyber_sentinel_x", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Check forum member directories and code commit histories for pseudonym shadow_operator_01", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Investigate open profile registrations across developer networks for username byte_hunter_42", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Determine if online identity zero_vector_88 has public profiles on GitHub, GitLab, or Keybase", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Scan social media platforms to identify accounts linked to nickname quantum_hacker_7", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Perform handle enumeration across open-source communities for username stealth_coder_33", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Track public discussion forum threads and code repositories referencing alias hex_infiltrator", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Audit web presence and platform accounts registered under handle binary_ranger_55", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Search technical bug-bounty leaderboard listings for user handle apex_bounty_seeker", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Look up open profile biographies and avatar hashes for username dark_tracer_12", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Gather digital footprint intelligence associated with online handle cipher_rebel_90", "expected_intent": "OSINT_USERNAME"},

    # 9. OSINT_PHONE (12)
    {"prompt": "Identify telecom carrier, line type, and geographic origin for telephone number +1-206-555-0144", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Lookup mobile network operator and porting status for subscriber number +44-20-7946-0922", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Determine international dialing prefix and region details for telephone contact +49-30-901820", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Check if phone number +1-312-555-0188 is registered as a VOIP virtual service provider", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Verify E.164 formatting, country allocation, and validity for cellular line +33-1-42685555", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Gather carrier routing information and caller ID registry records for number +61-2-93744000", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Determine originating telecom company and state jurisdiction for telephone +1-415-555-0199", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Audit telephone number +81-3-5555-0143 to discover carrier name and mobile network code", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Look up reverse directory listings and spam risk reputation for caller +1-646-555-0177", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Investigate country code, area exchange, and network carrier for subscriber +41-22-555-0123", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Check telecom routing database to determine carrier type for business line +1-512-555-0132", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Evaluate phone number formatting and original operator assignment for +34-91-555-0181", "expected_intent": "OSINT_PHONE"},

    # 10. CTF_AND_CHALLENGE_ANALYSIS (12)
    {"prompt": "Extract the hidden flag from this steganographic image file using LSB plane extraction", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Decompile this stripped 64-bit ELF binary to locate the string validation routine", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Analyze this custom multi-round XOR cipher ciphertext to recover the plaintext secret", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Construct a ret2libc payload calculating system() address offset from leaked puts() pointer", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Solve this crypto challenge involving small RSA public exponent e=3 and unpadded messages", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Examine this obfuscated JavaScript bookmarklet to decode the hidden CTF challenge solution", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Identify the real challenge token among multiple decoy flags inserted in memory buffers", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Bypass the anti-debugging ptrace check in this Linux challenge executable to reach main()", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Reverse engineer this webassembly Wasm bytecode module to find the password check logic", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Break this substitution cipher using bigram frequency distribution analysis to read the flag", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Exploit an integer overflow flaw in this challenge binary to achieve buffer size manipulation", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Decode this nested multi-layer base85 and rot13 payload to uncover the contest prize flag", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},

    # 11. CODING_AND_RESEARCH (12)
    {"prompt": "Write a python function implementing an LRU cache with O(1) retrieval and constant time eviction", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Provide a secure C implementation of constant-time memory comparison to mitigate timing attacks", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Develop a Go microservice handler that enforces token bucket rate limiting per client API key", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Write an async Python script using aiohttp to concurrently query JSON endpoints with backoff", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Show how to implement Argon2id password hashing securely using modern cryptography libraries", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Write a Rust function that validates incoming JSON web tokens without external unvetted crates", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Research the mathematical foundations of lattice-based cryptography and post-quantum standards", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Provide a Python class implementing a deterministic finite automaton for lexing tokens", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Develop an idiomatic TypeScript wrapper for calling authenticated REST APIs with typed schemas", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Write a bash utility that monitors disk space utilization and dispatches alerts via curl", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "How does the zero-knowledge Succinct Non-Interactive Argument of Knowledge (SNARK) protocol function mathematically?", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Construct an asynchronous token bucket request throttling class using Python asyncio and time metrics", "expected_intent": "CODING_AND_RESEARCH"},

    # 12. AUDIT_VERIFY (12)
    {"prompt": "Validate the SHA-256 rolling ledger hash chain in the SQLite security log database", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Verify that cryptographic HMAC checkpoints match the external signature state for the ledger", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Perform an integrity audit on the assessment events table to confirm zero deleted records", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Check whether database triggers prevented unauthorized update operations on historical events", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Inspect the tamper-evident audit ledger sequence numbering to detect missing transaction blocks", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Validate digital signatures on assessment audit checkpoints to ensure immutable log preservation", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Run cryptographic verification algorithms across all recorded ledger entries to prove provenance", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Check if any audit database event has been modified post-execution by inspecting prev_hash linkage", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Generate a cryptographic ledger compliance report proving uncompromised audit trail integrity", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Verify the HMAC signature key rotation manifest for recent assessment audit transactions", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Detect potential rollback tampering attempts by checking the audit ledger checkpoint sidecar", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Audit recent database operations against external ledger commitments to confirm zero discrepancies", "expected_intent": "AUDIT_VERIFY"},

    # 13. FILE_METADATA_ANALYSIS (12)
    {"prompt": "Calculate Shannon entropy across the binary file sections to detect packed code segments", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Extract EXIF metadata tags, camera serials, and GPS coordinate points from this JPEG image", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Analyze Portable Executable PE header timestamps, section names, and import tables", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Inspect PDF document metadata properties to identify author usernames and creation software", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Calculate cryptographic checksums MD5, SHA-1, and SHA-256 for this suspicious uploaded file", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Check the entropy profile of this sample to determine if payload data is encrypted or compressed", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Extract Mach-O header architecture flags and linked dynamic library dependencies from binary", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Triage this suspicious Office document to inspect embedded VBA macro streams and OLE objects", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Inspect digital authenticode signatures and certificate issuer chains on this Windows binary", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Extract string literals and embedded URLs from the data section of this unknown binary artifact", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Analyze ELF program headers and dynamic symbol tables to identify imported libc functions", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Parse archive file header structures to verify zip slip directory traversal risks in entries", "expected_intent": "FILE_METADATA_ANALYSIS"},

    # 14. TOOL_DETECTION (12)
    {"prompt": "Scan the current operating system environment to identify available security assessment binaries", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Check which network exploration and reconnaissance utilities are installed on system PATH", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Detect whether Wireshark, tshark, or tcpdump are available for capturing network traffic", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Audit system PATH to verify presence of vulnerability assessment tools like nikto or sqlmap", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "List available command execution adapters and platform runtimes configured in RedLoop", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Inspect local environment capabilities to verify if Docker and WSL subcomponents are active", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Determine which web fuzzing binaries like ffuf, gobuster, or feroxbuster are installed locally", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Query the system to report software versions for installed cybersecurity testing packages", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Check whether Metasploit framework or msfconsole binaries are accessible on the host", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Verify the operational availability of forensic extraction software like volatility or binwalk", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Scan local system utilities to discover supported exploitation and reconnaissance adapters", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Report installed software status and execution environment prerequisites for penetration testing", "expected_intent": "TOOL_DETECTION"},

    # 15. LIFECYCLE (12)
    {"prompt": "Halt the local assessment API daemon and release bound network ports gracefully", "expected_intent": "LIFECYCLE"},
    {"prompt": "Trigger a graceful reload of configuration parameters and refresh provider credentials", "expected_intent": "LIFECYCLE"},
    {"prompt": "Check the running health status and uptime metrics of the RedLoop background worker processes", "expected_intent": "LIFECYCLE"},
    {"prompt": "Shut down the loopback web console service listening on port 8765 cleanly", "expected_intent": "LIFECYCLE"},
    {"prompt": "Restart the core copilot orchestration service to apply updated environment settings", "expected_intent": "LIFECYCLE"},
    {"prompt": "Display active process IDs and thread pool allocation for background assessment workers", "expected_intent": "LIFECYCLE"},
    {"prompt": "Initialize runtime logging directories and verify state database access permissions", "expected_intent": "LIFECYCLE"},
    {"prompt": "Flush ephemeral memory caches and re-synchronize local assessment workspace state", "expected_intent": "LIFECYCLE"},
    {"prompt": "Stop all active background worker jobs and exit the CLI management process safely", "expected_intent": "LIFECYCLE"},
    {"prompt": "Verify system health indicators and operational readiness probes across all sub-services", "expected_intent": "LIFECYCLE"},
    {"prompt": "Terminate pending execution threads and shutdown the local assessment runtime cleanly", "expected_intent": "LIFECYCLE"},
    {"prompt": "Reload the application configuration file from disk without interrupting ongoing tasks", "expected_intent": "LIFECYCLE"},

    # 16. FOLLOW_UP_ON_ACTIVE_INVESTIGATION (12)
    {"prompt": "In our current active investigation, what specific vulnerability was flagged on the API gateway?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Can you provide more technical details regarding the finding we just discussed?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Pull the raw evidence records linked to the high-severity alert discovered in this case", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "What additional testing steps should we undertake next for this active security incident?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Review the latest findings logged in our current assessment session and suggest priorities", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Regarding the SQL injection issue discovered earlier, show the complete reproduction payload", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Continue evaluating the open incident case ticket and check for related lateral alerts", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Fetch the cryptographically hashed response evidence associated with the previous finding", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "What was the CVSS base score assigned to the finding we analyzed in the previous turn?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Proceed with the next phase of investigation for the open target compromise ticket", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Explain the business impact and exploitation prerequisites for the alert under review", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Summarize the current progress and outstanding investigative questions in this case", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},

    # 17. GENERAL_CHAT (12)
    {"prompt": "Explain the difference between symmetric block ciphers and stream ciphers in data encryption", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What security benefits does Address Space Layout Randomization (ASLR) provide against buffer overflows?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "How does the OAuth 2.0 authorization code flow protect client application credentials?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Describe the operational mechanics of Cross-Site Request Forgery (CSRF) and anti-CSRF token defense", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What is the purpose of Certificate Transparency logs in modern Public Key Infrastructure?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Explain how the Diffie-Hellman ephemeral key exchange establishes forward secrecy in TLS", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What are the key security distinctions between discretionary and mandatory access control models?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "How does DNS over HTTPS (DoH) improve user privacy compared to traditional plaintext DNS?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Describe common mitigation strategies against Server-Side Request Forgery (SSRF) vulnerabilities", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What role does the Content Security Policy (CSP) HTTP header play in mitigating XSS attacks?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Explain the architectural concepts behind zero-trust network architectures and continuous verification", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "How does the bcrypt hashing function use work factors to resist hardware-accelerated brute forcing?", "expected_intent": "GENERAL_CHAT"},
]

print(f"Total candidate prompts defined: {len(CANDIDATES)}")

# Verification of 0 hash overlap and 0 6-gram overlap
final_items = []
exact_overlap_count = 0
ngram_overlap_count = 0

for i, item in enumerate(CANDIDATES, 1):
    p = item["prompt"].strip()
    p_lower = p.lower()
    
    # 1. Exact hash / string check
    if p_lower in prior_prompt_set:
        print(f"EXACT OVERLAP FOUND: {p}")
        exact_overlap_count += 1
        continue
        
    # 2. 6-gram overlap check
    toks = tokenize(p)
    ngs = get_ngrams(toks, 6)
    overlap = ngs.intersection(prior_6grams)
    if overlap:
        print(f"6-GRAM OVERLAP FOUND in prompt: '{p}': {overlap}")
        ngram_overlap_count += 1
        continue
        
    final_items.append({
        "id": f"v4-{i:03d}",
        "prompt": p,
        "expected_intent": item["expected_intent"]
    })

print(f"\nVerification Results:")
print(f"  Exact Overlaps: {exact_overlap_count}")
print(f"  6-Gram Overlaps: {ngram_overlap_count}")
print(f"  Final Valid Items: {len(final_items)}")

assert exact_overlap_count == 0, f"Gate failed: {exact_overlap_count} exact overlaps found!"
assert ngram_overlap_count == 0, f"Gate failed: {ngram_overlap_count} 6-gram overlaps found!"
assert len(final_items) >= 200, f"Gate failed: only {len(final_items)} items generated (need >= 200)!"

out_path = Path("tests/fixtures/eval/intent_holdout_v4.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(final_items, f, indent=2)

print(f"Successfully generated {out_path} with {len(final_items)} clean, un-contaminated prompts!")
