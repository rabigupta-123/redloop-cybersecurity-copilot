import json

with open("artifacts/mismatches_v2.json", encoding="utf-8") as f:
    mismatches = json.load(f)

print(f"Total mismatches to analyze: {len(mismatches)}")

categories = {
    "cat_a_ambiguous": [],
    "cat_b_routing_bug": [],
    "cat_c_fixture_label": []
}

for m in mismatches:
    idx = m["idx"]
    p = m["prompt"]
    exp = m["expected"]
    pred = m["predicted"]
    
    # Check for Category C: Wrong or inconsistent intent labels in fixture
    # For example, if the prompt is asking a conceptual question or generic chat but labeled something else
    # Or if a prompt is asking for coding but labeled CTF
    if "Extract audio tag metadata, encoder version, and copyright comments from recording.wav." in p:
        # Prompt is inspecting audio file metadata, but fixture expected CTF_AND_CHALLENGE_ANALYSIS instead of FILE_METADATA_ANALYSIS!
        categories["cat_c_fixture_label"].append((m, "Prompt is extracting audio metadata from .wav file, expected CTF instead of FILE_METADATA_ANALYSIS"))
    elif "Examine PowerShell script block logging (Event 4104) for obfuscated base64 commands." in p:
        # Prompt is analyzing Event 4104 logs for obfuscated commands, expected FORENSICS_AND_LOG_ANALYSIS, but predicted CTF because of 'obfuscated base64'
        categories["cat_a_ambiguous"].append((m, "Ambiguous: Contains both log analysis (Event 4104) and deobfuscation/CTF keywords"))
    elif "Explain the tcpdump command to capture and write all DNS traffic to a pcap file." in p:
        # Expected KALI_COMMAND_ASSISTANCE, predicted FORENSICS_AND_LOG_ANALYSIS because of pcap/DNS traffic
        categories["cat_a_ambiguous"].append((m, "Ambiguous: Asking for tcpdump command line (Kali) vs traffic capture analysis (Forensics)"))
    elif exp == "REPORT_GENERATION":
        # Category B: router bug where 'assessment' or 'comprehensive' in report prompt triggers run_assessment before report_generate
        categories["cat_b_routing_bug"].append((m, "Routing bug: 'assessment' keyword falsely triggers vulnerability assessment over report generation"))
    elif exp == "AUDIT_VERIFY":
        # Category B: router bug where audit ledger/tamper checks lack pattern matching for natural phrases
        categories["cat_b_routing_bug"].append((m, "Routing bug: audit verification pattern requires rigid exact 2-word match"))
    elif exp == "CODING_AND_RESEARCH":
        # Category B: router bug where 'is_coding' requires rigid 'write a python' without adjectives
        categories["cat_b_routing_bug"].append((m, "Routing bug: 'is_coding' pattern too rigid to match 'write a secure python'"))
    elif exp == "OSINT_USERNAME":
        # Category B: router bug where username investigation requires exact phrase 'investigate username'
        categories["cat_b_routing_bug"].append((m, "Routing bug: username check misses 'handle <x>' and 'for username <x>'"))
    elif exp == "OSINT_DOMAIN":
        # Category B: router bug where domain OSINT misses DNS record queries (SPF, DKIM, DMARC, CAA, SOA, MX)
        categories["cat_b_routing_bug"].append((m, "Routing bug: domain OSINT missing DNS record types (SPF, DKIM, DMARC, CAA, SOA, MX)"))
    elif exp == "FILE_METADATA_ANALYSIS":
        # Category B: router bug where file analysis misses PE, ELF, OLE, Mach-O headers and format inspection
        categories["cat_b_routing_bug"].append((m, "Routing bug: metadata pattern misses PE/ELF/OLE/Mach-O and file extension keywords"))
    elif exp == "AUTHORIZED_RECONNAISSANCE":
        # Category B: router bug where authorized network sweep/probe/discovery missing from has_scan_verb
        categories["cat_b_routing_bug"].append((m, "Routing bug: authorized sweep/probe/discovery missing from active recon rules"))
    elif exp == "VULNERABILITY_ASSESSMENT":
        # Category B: router bug where vulnerability check/evaluation verbs not in has_assess_verb
        categories["cat_b_routing_bug"].append((m, "Routing bug: vulnerability check/evaluation verbs not in has_assess_verb"))
    elif exp == "CTF_AND_CHALLENGE_ANALYSIS":
        # Category B: router bug where CTF challenge terms (ret2libc, steganography, hidden flag) missing from is_ctf
        categories["cat_b_routing_bug"].append((m, "Routing bug: CTF challenge terms missing from is_ctf"))
    elif exp == "KALI_COMMAND_ASSISTANCE":
        # Category B: router bug where kali commands (masscan, ffuf, tshark, sslscan) missing
        categories["cat_b_routing_bug"].append((m, "Routing bug: Kali assistance missing tool names and 'how do i configure/use'"))
    elif exp == "TARGET_CLARIFICATION_REQUIRED":
        categories["cat_b_routing_bug"].append((m, "Routing bug: scan verbs without target fall through to general chat"))
    elif exp == "OSINT_IP":
        categories["cat_b_routing_bug"].append((m, "Routing bug: IP threat reputation/VPN check not routed to OSINT_IP"))
    elif exp == "GRAPH_AND_INVESTIGATION":
        categories["cat_b_routing_bug"].append((m, "Routing bug: graph query phrases missing"))
    elif exp == "FORENSICS_AND_LOG_ANALYSIS":
        categories["cat_b_routing_bug"].append((m, "Routing bug: log analysis phrases missing"))
    else:
        categories["cat_a_ambiguous"].append((m, "Adversarial or ambiguous prompt"))

print(f"\nCategorization breakdown:")
print(f"Category (a) Genuinely ambiguous/adversarial: {len(categories['cat_a_ambiguous'])}")
print(f"Category (b) Real routing bugs: {len(categories['cat_b_routing_bug'])}")
print(f"Category (c) Missing/wrong fixture labels: {len(categories['cat_c_fixture_label'])}")

