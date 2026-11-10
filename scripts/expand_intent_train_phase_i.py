"""Expand lowest-recall classes with >= 15 diverse examples each in intent_train_v2.json."""
import json
from collections import Counter
from pathlib import Path

train_path = Path("tests/fixtures/eval/intent_train_v2.json")
with open(train_path, "r", encoding="utf-8") as f:
    data = json.load(f)

existing_prompts = {d["prompt"].strip().lower() for d in data}

additions = [
    # 1. LIFECYCLE (18 items)
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Halt all background worker routines and stop the daemon."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Pause the active assessment execution pipeline."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Resume the suspended assessment session."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Abort and cancel the active testing process immediately."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Check the status and uptime of the orchestrator service."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Perform a clean shutdown of the security testing framework."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Gracefully terminate the CLI runner and disconnect listeners."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Restart the core background services and refresh state."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Query daemon health metrics and active thread count."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Spin down worker threads and save persistent workspace state."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Cancel all queued assessment jobs and release locks."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Kill the background scan tasks and flush temporary buffers."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Inspect runtime resource usage and server process uptime."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Reboot the assessment server instance without data loss."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Halt execution and unload loaded plugins."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Put the current assessment runner into standby mode."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Stop the local proxy listener and teardown test services."},
    {"expected_intent": "LIFECYCLE", "category": "lifecycle", "prompt": "Signal worker pool to complete in-flight tasks and exit."},

    # 2. KALI_COMMAND_ASSISTANCE (18 items)
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "How do I run a stealth SYN scan using nmap command line syntax?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "What is the syntax for gobuster directory brute-forcing with a wordlist?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Provide the hashcat command to crack NTLM hashes with rockyou.txt."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Give me the hydra command line flags to brute force SSH logins."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "What Kali command can I use to inspect wireless packets with airmon-ng?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Show me how to invoke sqlmap with custom tamper scripts."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "What is the command line invocation for wpscan to enumerate plugins?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "How to configure responder in Kali for LLMNR poisoning?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Show the nmap command to scan top 100 ports with version detection."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "What command in Kali Linux performs arp spoofing using arpspoof?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Help me construct a tcpdump command filter for DNS traffic."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Show me syntax for ffuf fuzzing HTTP POST body parameters."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "How do I run amass enum to find passive subdomains from terminal?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "What CLI flags should I pass to nikto for tuning specific tests?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Show the smbclient command to connect anonymously to an SMB share."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Provide the john the ripper command format for /etc/shadow hashes."},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "How to use socat to set up an encrypted reverse shell relay?"},
    {"expected_intent": "KALI_COMMAND_ASSISTANCE", "category": "kali", "prompt": "Syntax for feroxbuster to perform recursive endpoint discovery."},

    # 3. REPORT_GENERATION (18 items)
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Export an HTML vulnerability assessment report for stakeholders."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Generate a penetration test summary dossier with severity breakdowns."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Compile all discovered vulnerabilities into a deliverable PDF brief."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Produce an executive security briefing document from current findings."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Create a technical audit report containing proof-of-concept steps."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Build a markdown summary ledger detailing confirmed security issues."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Export assessment observations into a presentation-ready executive report."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Synthesize identified risk vectors into a comprehensive client report."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Generate a remediation roadmap document based on discovered flaws."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Prepare an executive findings report summarizing business risk exposure."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Compile an engagement closeout report detailing all validated findings."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Generate a compliance audit report linking findings to NIST controls."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Produce a downloadable PDF vulnerability portfolio for our audit team."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Format the security assessment results into a structured markdown report."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Generate an executive summary slide deck or report of our test results."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Assemble all logged vulnerabilities into a finalized assessment report."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Draft a formal penetration test report covering identified ingress vectors."},
    {"expected_intent": "REPORT_GENERATION", "category": "report", "prompt": "Export an executive overview report of our threat exposure and cvss scores."},

    # 4. CODING_AND_RESEARCH (18 items)
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Write a Python script to parse and extract emails from a text dump."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Explain how race condition vulnerabilities work in web applications."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Can you review this code snippet for SQL injection vulnerabilities?"},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Develop a regex pattern in Python to validate IPv6 addresses."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Explain the security implications of weak cryptographic salts in password hashing."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Write an async Python function to probe multiple HTTP endpoints concurrently."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Research the difference between blind SQL injection and error-based SQL injection."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "How does prototype pollution occur in JavaScript applications?"},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Write a script to automate base64 decoding of multi-layered payloads."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Explain how memory corruption bugs like buffer overflows are mitigated by ASLR."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Provide a code example in Python for parsing pcap files using scapy."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "What are the key security differences between OAuth 2.0 and SAML 2.0?"},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Write a custom parser in Python for CEF security syslog messages."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Explain how cross-site request forgery tokens prevent CSRF attacks."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Develop a Python helper to calculate SHA-256 and MD5 hashes of local files."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "How does DOM-based XSS differ from reflected cross-site scripting?"},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Write a script to clean and deduplicate domain lists from OSINT queries."},
    {"expected_intent": "CODING_AND_RESEARCH", "category": "coding", "prompt": "Explain the mechanism behind Kerberoasting attacks in Active Directory."},

    # 5. FILE_METADATA_ANALYSIS (18 items)
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Extract EXIF metadata from this uploaded JPEG image file."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Inspect the embedded author and modification stamps in this Word document."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Analyze this PDF file for hidden metadata tags, creator, and creation dates."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Extract GPS location coordinates from the EXIF headers of this photo."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Inspect the header structures and metadata fields of this binary artifact."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Check this document file for revision history and user metadata leaks."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Extract embedded thumbnail images and camera information from this graphic."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Analyze the metadata of this XLSX spreadsheet for creator usernames."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Read the PE file header timestamps and compile metadata from this executable."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Inspect the EXIF tags of this file to determine device model and serial number."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Check metadata of this PNG file for trailing data or steganographic chunks."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Extract creation timestamp, author name, and application info from this document."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Analyze this media file for id3 metadata tags and comment strings."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Inspect PDF document catalog and info dictionary for sensitive strings."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Extract file metadata attributes including mime type, magic bytes, and timestamps."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Audit this image file to see if GPS longitude and latitude are recorded."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Extract metadata properties from this presentation file."},
    {"expected_intent": "FILE_METADATA_ANALYSIS", "category": "metadata", "prompt": "Inspect EXIF and XMP metadata streams in this digital photography file."},

    # 6. FOLLOW_UP_ON_ACTIVE_INVESTIGATION (18 items)
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "What were the findings on the secondary host from our earlier scan?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Can you elaborate further on the SQL injection vulnerability found earlier?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Pull the raw network logs associated with that high severity finding."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Review the next action items for the ongoing security assessment."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Regarding the previous open port discovery, what service was running on 8443?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Continue inspecting the open ports we discovered in the last task."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "What is the current status of the findings logged in this investigation?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Drill down into the vulnerability details we captured in step 3."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Retrieve the stored evidence artifacts for the previous vulnerability alert."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Following up on the domain scan, did we verify the SPF record issue?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Check the previous task execution output and summarize remaining gaps."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Can we re-examine the response headers from the initial target probe?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Provide more context on the weak cipher suites identified in the last scan."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "What additional reconnaissance should we perform on the discovered subdomains?"},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Proceed with the next step of the incident response workflow."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Review the evidence captured during our previous investigation phase."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "Follow up on the anomalous HTTP status codes seen in our prior test."},
    {"expected_intent": "FOLLOW_UP_ON_ACTIVE_INVESTIGATION", "category": "followup", "prompt": "What were the credential issues reported in our ongoing case?"},

    # 7. TOOL_DETECTION (18 items)
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Detect whether nmap and nikto are installed in the local path."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Scan the environment to check which security assessment tools are available."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Which vulnerability scanners and reconnaissance binaries are present?"},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Check if gobuster or dirb are installed on this system."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Verify if docker engine and sandbox CLI tools are accessible locally."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "What command line utilities are currently installed for penetration testing?"},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Probe system PATH for the presence of curl, wget, and python interpreters."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Check if tshark or tcpdump packet analyzers are available in the runtime."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Audit the local machine for installed OSINT and reconnaissance binaries."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Detect installed security software tools and execution adapters."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Verify presence of nuclei, subfinder, and httpx in system PATH."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Check whether the required terminal assessment dependencies are installed."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "List all detected security scanners and their version numbers."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Identify which penetration testing CLI utilities are installed on this host."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Check system environment to see if hashcat or john are installed."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Detect available network enumeration and port scanning binaries."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Verify if web application security testing tools are detected on this workstation."},
    {"expected_intent": "TOOL_DETECTION", "category": "tools", "prompt": "Check which exploitation simulation tools are present in our environment."},

    # 8. FORENSICS_AND_LOG_ANALYSIS (18 items)
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Analyze this auth.log file for brute-force SSH authentication attempts."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Parse these web server access logs to identify automated directory scanners."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Inspect the Windows event logs for suspicious service installation events."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Analyze this pcap packet capture for beaconing C2 network communication."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Review firewall logs for high-frequency connection attempts from foreign IPs."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Search syslog records for privilege escalation attempts via sudo."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Analyze this web application access log for SQL injection attack patterns."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Examine these system audit logs for signs of log tampering or clearing."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Perform timeline analysis on these extracted system event logs."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Analyze DNS query logs for anomalous high-entropy domain lookups."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Inspect these proxy logs for unauthorized data staging or exfiltration."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Parse nginx error logs to identify application crashes and stack trace leaks."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Identify suspicious outbound connections in this netflow capture."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Analyze these bash history files for evidence of operator persistence."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Examine Linux journal logs for anomalous systemd unit creations."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Inspect packet capture file to identify cleartext credential transmissions."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Extract HTTP user-agent strings from this server access log for anomaly scoring."},
    {"expected_intent": "FORENSICS_AND_LOG_ANALYSIS", "category": "forensics", "prompt": "Search event logs for unusual logon type 3 network logons during off-hours."},

    # 9. OSINT_USERNAME (18 items)
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Investigate the digital footprint for handle 'cyber_phantom_99'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Search social media platforms and forums for username 'net_spectre'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Find public accounts and online profiles registered under handle 'dark_hound'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Lookup username 'crypto_wizard' across developer communities and code repos."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Check if handle 'null_operator' exists on Github, Twitter, or Reddit."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Perform OSINT reconnaissance on user handle 'ghost_shell_07'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Query username directories for profile 'binary_reaper'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Search for online footprint associated with username 'shadow_pilot'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Look up public forums and discussions authored by alias 'byte_warrior'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Check social network accounts and repositories for username 'red_vortex'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Investigate online presence and code commits for handle 'cipher_mind'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Find online identity and registration history for username 'apex_hunter'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Locate user profiles and alias matches for 'zero_trace_9'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Search for public profiles linked to developer username 'stack_overflow_guru'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Perform an alias footprint search for username 'stealth_runner'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Scan online communities to uncover accounts using nickname 'iron_sentry'."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Check whether username 'skyline_coder' is registered across known platforms."},
    {"expected_intent": "OSINT_USERNAME", "category": "osint", "prompt": "Investigate developer profile and commit history for handle 'quantum_dev'."},
]

added_count = 0
for item in additions:
    p_norm = item["prompt"].strip().lower()
    if p_norm not in existing_prompts:
        item["id"] = f"train-phase-i-{len(data) + 1:04d}"
        data.append(item)
        existing_prompts.add(p_norm)
        added_count += 1

with open(train_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"Added {added_count} training examples. New total: {len(data)}")
counts = Counter(d["expected_intent"] for d in data)
for intent, count in sorted(counts.items()):
    print(f"  {intent:<35} {count}")

