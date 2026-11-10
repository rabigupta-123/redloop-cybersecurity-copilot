"""Generate fresh intent_holdout_v5.json with 0 hash and 0 6-gram overlap with (train + v1 + v2 + v3 + v4)."""
import json
import re
from pathlib import Path

def tokenize(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text.lower())

def get_ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    return set(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))

# Load all prior datasets: train, v1, v2, v3, v4
prior_files = [
    Path("tests/fixtures/eval/intent_train_v2.json"),
    Path("tests/fixtures/eval/intent_holdout_v1.json"),
    Path("tests/fixtures/eval/intent_holdout_v2.json"),
    Path("tests/fixtures/eval/intent_holdout_v3.json"),
    Path("tests/fixtures/eval/intent_holdout_v4.json"),
]

prior_prompts = []
for p in prior_files:
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            prior_prompts.extend(x["prompt"] for x in data)

prior_prompt_set = {p.strip().lower() for p in prior_prompts}
prior_6grams = set()
for p in prior_prompts:
    toks = tokenize(p)
    prior_6grams.update(get_ngrams(toks, 6))

print(f"Total prior prompts across train+v1+v2+v3+v4: {len(prior_prompts)}")
print(f"Total prior 6-grams across train+v1+v2+v3+v4: {len(prior_6grams)}")

# Generation method: Conversational & Operator-Style inquiries per intent
# 12 prompts x 17 classes = 204 prompts
CANDIDATES = [
    # 1. REPORT_GENERATION (12)
    {"prompt": "Can you package our verified assessment vulnerabilities into a clean PDF executive report?", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Write up an executive-level vulnerability report summarizing the results of our external test.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "I need a markdown report generated for the management team showing all discovered flaws.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Please export the full security assessment documentation as an HTML report.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Create a finalized report detailing the high and critical severity items we uncovered.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Draft an engagement report that includes CVSS scores, remediation advice, and executive summaries.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Can you generate a technical penetration testing report with step-by-step evidence?", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Produce a downloadable assessment report covering all perimeter security findings.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Format all logged vulnerability findings from today into an executive markdown report.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Generate a compliance and vulnerability report ready for client presentation.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Export our test findings into an executive report with an overview for stakeholders.", "expected_intent": "REPORT_GENERATION"},
    {"prompt": "Assemble a comprehensive vulnerability assessment report with recommendations.", "expected_intent": "REPORT_GENERATION"},

    # 2. GRAPH_AND_INVESTIGATION (12)
    {"prompt": "Show me an interactive graph linking the compromised nodes and open services.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Can you render the attack path graph illustrating how the attacker reached domain admin?", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Display a visual diagram of the network topology connecting these hosts.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Visualize the relationships between the discovered subdomains and our internal network assets.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Generate an attack surface graph to visualize choke points in the network architecture.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Draw a graph depicting lateral movement vectors from workstation-01 to the file server.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Show the graph model of trust relationships between these cloud infrastructure entities.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Can you construct an entity graph mapping user accounts to sensitive storage buckets?", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Visualize the compromise propagation graph for the finance segment incident.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Render an attack graph showing how external services connect to backend microservices.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Export the topology graph showing interconnected servers and perimeter gateways.", "expected_intent": "GRAPH_AND_INVESTIGATION"},
    {"prompt": "Display an attack path visualization for the privilege escalation steps observed.", "expected_intent": "GRAPH_AND_INVESTIGATION"},

    # 3. AUDIT_VERIFY (12)
    {"prompt": "Run an integrity check on the assessment database audit ledger.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Verify the HMAC hash chain to ensure no audit entries were tampered with.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Can you validate the cryptographic signatures on our stored audit trail logs?", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Audit ledger verification: confirm all recorded transaction hashes match up.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Check if any records in the audit trail have broken cryptographic linkages.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Inspect the SQLite audit ledger table and verify integrity proof checkpoints.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Validate that the audit chain sequence numbers are strictly continuous and untampered.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Verify the digital signatures protecting our security audit ledger.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Check the tamper-evident audit records against the external checkpoint hash.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Verify audit log integrity to prove that no historical records were altered.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Execute an audit verification routine over the recorded operator commands.", "expected_intent": "AUDIT_VERIFY"},
    {"prompt": "Validate the SHA256 chain and HMAC anchors on all audit events.", "expected_intent": "AUDIT_VERIFY"},

    # 4. FORENSICS_AND_LOG_ANALYSIS (12)
    {"prompt": "Examine this auth.log file to spot failed SSH login attempts and brute force patterns.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Analyze these nginx web server access logs for traces of directory fuzzing or sql injection.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Can you parse this pcap file to identify DNS tunneling or beaconing activity?", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Review these Windows Security Event Logs to detect event ID 4624 type 3 logons.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Inspect these firewall connection logs for abnormal outbound traffic spikes.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Look through this syslog file to find unauthorized sudo command executions.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Analyze this Apache access log file for malicious user-agent strings and exploitation payloads.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Investigate this packet capture for cleartext passwords transmitted across port 21.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Perform forensic log analysis on these auditd events to spot privilege escalation.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Parse this Zeek conn.log dump to identify long-duration TCP sessions to unknown IPs.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Analyze these mail server logs for evidence of spam relaying or account takeover.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},
    {"prompt": "Inspect these endpoint security logs to track down malicious scheduled task creation.", "expected_intent": "FORENSICS_AND_LOG_ANALYSIS"},

    # 5. OSINT_IP (12)
    {"prompt": "Gather OSINT threat intelligence and ASN data for IP address 198.51.100.42.", "expected_intent": "OSINT_IP"},
    {"prompt": "Lookup WHOIS and geolocate the public IP 203.0.113.88.", "expected_intent": "OSINT_IP"},
    {"prompt": "Determine whether IP 192.0.2.115 is flagged on malicious blocklists or threat feeds.", "expected_intent": "OSINT_IP"},
    {"prompt": "Can you investigate IP 198.51.100.201 to see if it belongs to a VPN or Tor exit node?", "expected_intent": "OSINT_IP"},
    {"prompt": "Retrieve reverse DNS and BGP prefix routing info for 203.0.113.15.", "expected_intent": "OSINT_IP"},
    {"prompt": "Run an OSINT reputation check on 192.0.2.77 using public threat intelligence feeds.", "expected_intent": "OSINT_IP"},
    {"prompt": "Find out the registered organization and CIDR block for 198.51.100.170.", "expected_intent": "OSINT_IP"},
    {"prompt": "Query Shodan and passive DNS history for suspicious IP 203.0.113.99.", "expected_intent": "OSINT_IP"},
    {"prompt": "Look up abuse contacts and network allocations for address 192.0.2.222.", "expected_intent": "OSINT_IP"},
    {"prompt": "Perform an IP intelligence lookup on 198.51.100.5 to check for malicious activity.", "expected_intent": "OSINT_IP"},
    {"prompt": "Investigate whether 203.0.113.44 is listed on spam blocklists or botnet registries.", "expected_intent": "OSINT_IP"},
    {"prompt": "What autonomous system number and ISP owns the IP block containing 192.0.2.60?", "expected_intent": "OSINT_IP"},

    # 6. OSINT_DOMAIN (12)
    {"prompt": "Conduct passive intelligence gathering regarding the web property target-corp.example.com.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Lookup WHOIS records and registrar details for apex domain example-security.org.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Query crt.sh SSL certificate records to map out test-app.com subdomains.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Can you inspect DNS TXT records for cloud-gateway.net to verify SPF and DMARC posture?", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Gather DNS footprint and mail exchanger records for alpha-vendor.example.edu.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Investigate passive DNS history and name servers for enterprise-portal.org.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Check security headers and SSL certificate expiration on secure-login.example.com.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Run a domain OSINT inquiry on payment-api.sample-corp.com to find hosted subdomains.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Look up CAA records and DNSSEC validation status for safe-banking.example.org.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Perform an OSINT investigation on external domain vendor-cloud-sync.net.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Discover subdomains and associated cloud infrastructure for client-service.example.com.", "expected_intent": "OSINT_DOMAIN"},
    {"prompt": "Query historical WHOIS and domain registration records for test-lab-target.org.", "expected_intent": "OSINT_DOMAIN"},

    # 7. OSINT_EMAIL (12)
    {"prompt": "Investigate email address security-lead@target-domain.example.com for known data leaks.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Check if user.admin@sample-corp.org has been involved in public credential breaches.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Look up MX records and verify deliverability for contact@fintech-demo.net.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Perform an OSINT email investigation on victim_user_99@webmail-service.com.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Can you check haveibeenpwned data for address researcher@infosec-hub.org?", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Analyze email header sender authenticity for incoming message from billing@external-vendor.com.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Find online profiles and breach records associated with engineer.bob@tech-corp.org.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Search public breach repositories for leaks containing operator77@cyber-lab.net.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Verify if support-desk@cloud-provider.example.com uses disposable or custom mail routing.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Look up data breach history for executive-assistant@acme-enterprises.org.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Perform email footprint analysis on suspect.sender@phishing-alert.net.", "expected_intent": "OSINT_EMAIL"},
    {"prompt": "Check whether accounting@corp-holdings.example.com has exposed passwords in past paste dumps.", "expected_intent": "OSINT_EMAIL"},

    # 8. OSINT_USERNAME (12)
    {"prompt": "Search public forums and social platforms for accounts using username 'dark_spectre_99'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Investigate online footprint and code repositories belonging to user handle 'shadow_coder_v2'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Can you check if handle 'binary_phantom' is registered across Github, Reddit, and Twitter?", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Perform an OSINT search for username 'cipher_wolf_88' to locate active profiles.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Look up discussion board posts and open-source contributions by nickname 'null_root_42'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Find online presence and alias associations for operator 'stealth_hacker_7'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Query developer platforms and paste sites for activity under username 'quantum_sec_dev'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Check social networks and gaming forums for profiles matching username 'iron_sentinel_01'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Search for public accounts and forum threads authored by alias 'byte_bandit_x'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Conduct username reconnaissance across digital communities for handle 'apex_predator_net'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Investigate commit history and profile details for open-source username 'kernel_panic_9'.", "expected_intent": "OSINT_USERNAME"},
    {"prompt": "Discover accounts and public profiles associated with user nickname 'silent_observer_33'.", "expected_intent": "OSINT_USERNAME"},

    # 9. OSINT_PHONE (12)
    {"prompt": "Investigate international phone number +1-555-019-2834 to identify carrier and line type.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Perform a telecom OSINT lookup on phone number +44 20 7946 0912.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Look up carrier routing and location details for mobile number +1-800-555-0147.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Check if telephone number +49 30 901820 is a VoIP service or landline.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Can you determine the mobile network operator for phone number +1 212 555 0198?", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Perform an OSINT telephone check for digits +33 9 87 65 43 21 to see telecom operator.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Lookup country code, validity, and carrier info for phone number +61 2 9374 4000.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Check whether mobile line +1-773-555-9812 has spam reports or telemarketer flags.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Identify the originating telecom carrier for dialed number +81 6 6000 1234.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Perform an OSINT lookup on caller ID +1-415-555-0129 to extract carrier metadata.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Check telecom routing records and number portability for +44 1632 960987.", "expected_intent": "OSINT_PHONE"},
    {"prompt": "Lookup line type and geographic service area for phone number +1-206-555-0164.", "expected_intent": "OSINT_PHONE"},

    # 10. CTF_AND_CHALLENGE_ANALYSIS (12)
    {"prompt": "Help me solve this CTF reverse engineering puzzle involving a packed x86 binary.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Can you decode this base64 and ROT13 ciphertext string to extract the secret CTF flag?", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Analyze this steganography challenge image to find hidden strings in the least significant bits.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Decompile this Ghidra assembly snippet from a CTF binary to understand the password check function.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "How can I bypass this buffer overflow canary check in an x86_64 CTF exploit challenge?", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Inspect this RSA challenge with small public exponent e=3 and factorize the modulus.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Decode this multi-stage hexadecimal and XOR encoded payload to recover the challenge token.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Analyze this web CTF challenge where JWT signature verification is set to 'none'.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Assist in assembling return-oriented programming gadgets to bypass NX protections in this challenge.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Extract the hidden flag string hidden inside the color palette chunks of this challenge PNG.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "Analyze this format string vulnerability challenge in a 32-bit Linux ELF binary.", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},
    {"prompt": "How to exploit this timing attack challenge on a cryptographic HMAC comparison routine?", "expected_intent": "CTF_AND_CHALLENGE_ANALYSIS"},

    # 11. FILE_METADATA_ANALYSIS (12)
    {"prompt": "Inspect this uploaded photo to extract EXIF camera tags and GPS coordinates.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Can you parse the internal metadata and author properties from this Microsoft Word docx file?", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Analyze this PDF file's info dictionary to determine the creation software and modification date.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Extract embedded geolocation latitude and longitude metadata from this JPEG image.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Inspect the PE file header of this Windows executable to extract compile timestamps and section names.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Check the metadata of this Excel spreadsheet to see which user account last edited it.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Extract ID3 audio metadata tags including artist, album, and comment fields from this MP3 file.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Analyze this PNG file for extraneous metadata blocks or text chunks appended to the IEND marker.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Inspect the file header attributes, MIME type, and magic bytes for this uploaded artifact.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Check this PowerPoint presentation file for embedded revision history and creator usernames.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Extract EXIF and IPTC photographic metadata from this digital camera raw image.", "expected_intent": "FILE_METADATA_ANALYSIS"},
    {"prompt": "Inspect the file metadata to see if document revision history reveals confidential email addresses.", "expected_intent": "FILE_METADATA_ANALYSIS"},

    # 12. KALI_COMMAND_ASSISTANCE (12)
    {"prompt": "What is the Kali Linux command to run a fast TCP SYN port scan with Nmap?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Show me the terminal syntax for gobuster to find hidden web directories using a wordlist.", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "How do I invoke hashcat in Kali to crack SHA-512 crypt passwords with rockyou?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Which CLI parameters should I supply to hydra when brute-forcing an FTP login?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "What command line parameters do I pass to sqlmap to test for time-based blind injection?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Show the terminal command for running Nikto with evasion mode enabled.", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "How can I use tcpdump in Kali Linux to capture traffic filtered on destination port 53?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Show the terminal invocation of ffuf for discovering hidden URL query parameters.", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Show me how to run wpscan in Kali to enumerate WordPress usernames and installed plugins.", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "What command should I type in the Kali terminal to list active network interfaces with ip route?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "Provide the command syntax for amass enum to discover passive subdomains from terminal.", "expected_intent": "KALI_COMMAND_ASSISTANCE"},
    {"prompt": "How do I invoke john the ripper with a custom wordlist against an /etc/shadow extract?", "expected_intent": "KALI_COMMAND_ASSISTANCE"},

    # 13. CODING_AND_RESEARCH (12)
    {"prompt": "Write a Python script using asyncio to probe a list of URLs and record HTTP status codes.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Explain the technical difference between reflected cross-site scripting and DOM-based XSS.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Can you review this Python code to see if there is an insecure deserialization flaw?", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Develop a regular expression in Python that validates RFC-compliant email addresses.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Explain how the OAuth 2.0 PKCE flow protects against authorization code interception attacks.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Write a Python helper function to compute the SHA-256 checksum of a file in streaming chunks.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "How does memory corruption like use-after-free occur in C++ memory management?", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Write a script in Python to parse an Nmap XML output file and list all hosts with port 443 open.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Explain how Server-Side Request Forgery vulnerabilities can be used to pivot to cloud metadata APIs.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Can you write a Python snippet to extract all URLs from an HTML document using BeautifulSoup?", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Research and summarize how Content Security Policy headers mitigate modern XSS attacks.", "expected_intent": "CODING_AND_RESEARCH"},
    {"prompt": "Write a Python script that takes a list of IP addresses and groups them by CIDR subnet.", "expected_intent": "CODING_AND_RESEARCH"},

    # 14. TOOL_DETECTION (12)
    {"prompt": "Detect which penetration testing tools and network scanners are installed locally.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Check if Nmap, Nikto, or Gobuster are currently available in the system PATH.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Scan the local operating system to discover installed cybersecurity utilities.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Verify whether Docker engine and container runtime environments are accessible.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Which security assessment CLI tools and execution adapters are detected on this workstation?", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Probe the runtime environment to see if Python, curl, and wget binaries exist.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Check whether packet analysis utilities like Wireshark or tshark are installed.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Audit the system to list all recognized vulnerability assessment binaries.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Detect if password cracking utilities such as hashcat or john are installed in the path.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Scan the workstation environment to verify tool dependencies before starting an assessment.", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Which OSINT and web reconnaissance tools are currently installed on this host?", "expected_intent": "TOOL_DETECTION"},
    {"prompt": "Check whether the RedLoop assessment adapter binaries are present and functional.", "expected_intent": "TOOL_DETECTION"},

    # 15. LIFECYCLE (12)
    {"prompt": "Power down the active RedLoop copilot server and dismiss background runners.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Can you pause the currently running assessment execution pipeline?", "expected_intent": "LIFECYCLE"},
    {"prompt": "Resume the suspended security assessment session and continue where it left off.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Cancel the ongoing background scan and clean up temporary execution resources.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Restart the orchestrator service and reload configuration settings from disk.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Check the health, uptime, and active worker count of the assessment server.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Perform a clean shutdown of all background scanner threads and listeners.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Abort all pending assessment tasks and reset the worker queue state.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Display current server process status, memory footprint, and thread pool allocation.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Cease running the local web API process and unbind active listening sockets.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Put the assessment workbench into standby mode and flush ephemeral caches.", "expected_intent": "LIFECYCLE"},
    {"prompt": "Gracefully reload all plugin adapters and restart the execution scheduler.", "expected_intent": "LIFECYCLE"},

    # 16. FOLLOW_UP_ON_ACTIVE_INVESTIGATION (12)
    {"prompt": "Regarding the vulnerability we just discovered, can you show me the full HTTP response headers?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "What were the open ports detected on the primary database server in our active case?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Can you pull the raw network evidence associated with alert finding-002?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "In our ongoing investigation, what is the current risk rating of the perimeter gateway?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Follow up on the weak SSL cipher suites identified during the earlier scan.", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Can we look deeper into the anomalous DNS responses logged in step 4?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Review the next recommended action items for our open assessment ticket.", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "What did the previous reconnaissance step reveal about the secondary mail server?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Fetch the saved proof-of-concept evidence files from that earlier unauthenticated API issue.", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Continue investigating the directory traversal flaw discovered in the active session.", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Following up on that open port 8443, what application version was running behind TLS?", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},
    {"prompt": "Summarize the remaining gaps and unresolved alerts from our current incident file.", "expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION"},

    # 17. GENERAL_CHAT (12)
    {"prompt": "Good morning, how are you doing today?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Tell me a joke about computer networking or firewalls.", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What is the capital city of Australia?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Can you explain what the OSI model seven layers represent in simple terms?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Who wrote the novel Neuromancer in 1984?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Help me brainstorm some catchy names for our new cybersecurity podcast.", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What are some general tips for studying effectively for the CISSP exam?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Thank you for the quick explanation, that was really helpful!", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Can you recommend a good sci-fi movie about artificial intelligence?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "What is the difference between a microcontroller and a microprocessor?", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Hello! I am ready to start working on our project today.", "expected_intent": "GENERAL_CHAT"},
    {"prompt": "Could you write a short haiku about network packets traveling across the internet?", "expected_intent": "GENERAL_CHAT"},
]

print(f"\nEvaluating candidate pool: {len(CANDIDATES)} candidates...")

# Verify 0 hash overlap and 0 6-gram overlap with ALL prior datasets
hash_collisions = 0
ngram_collisions = []

v5_6grams = set()
v5_prompts = []

for idx, cand in enumerate(CANDIDATES):
    p = cand["prompt"]
    p_norm = p.strip().lower()
    
    # 1. Exact match check
    if p_norm in prior_prompt_set:
        print(f"ERROR: Exact match collision on candidate {idx}: {p}")
        hash_collisions += 1
        
    # 2. 6-gram overlap check
    toks = tokenize(p)
    ngrams = get_ngrams(toks, 6)
    overlap = ngrams.intersection(prior_6grams)
    if overlap:
        print(f"ERROR: 6-gram collision on candidate {idx}: {overlap} in '{p}'")
        ngram_collisions.append((p, overlap))
        
    v5_6grams.update(ngrams)
    cand_obj = {
        "id": f"v5-{idx+1:03d}",
        "prompt": p,
        "expected_intent": cand["expected_intent"]
    }
    v5_prompts.append(cand_obj)

print(f"Exact match collisions: {hash_collisions}")
print(f"6-gram collisions with prior sets: {len(ngram_collisions)}")

if hash_collisions == 0 and len(ngram_collisions) == 0:
    out_path = Path("tests/fixtures/eval/intent_holdout_v5.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(v5_prompts, f, indent=2)
    print(f"\nSUCCESS! Created {out_path} with {len(v5_prompts)} prompts.")
    print("0 exact match collisions and 0 6-gram overlaps verified against (train + v1 + v2 + v3 + v4).")
else:
    print("\nFAILED: Overlaps detected. Please fix collisions before writing v5 holdout.")
    exit(1)
