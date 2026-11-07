---
title: "Memory Forensics & Volatility 3 Analysis Guide"
tags: ["forensics", "memory", "volatility", "incident-response", "malware"]
source: "SANS FOR508 / Volatility Foundation"
---

# Memory Forensics & Volatility 3 Analysis Guide
## Source & Authority
SANS FOR508 Advanced Incident Response and Threat Hunting; Volatility 3 Documentation.

## Core Analysis Plugins
```bash
# List active processes and parent-child hierarchy
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw windows.pstree

# Identify active network connections and listening sockets
python3 vol.py -f memory.raw windows.netscan

# Detect injected code, shellcode, and hollowed memory regions
python3 vol.py -f memory.raw windows.malfind

# Dump memory image of suspicious process
python3 vol.py -f memory.raw -o dump/ windows.dumpfiles --pid <PID>
```
## Key Indicators
- Process unlinking from active process list (`windows.psscan` reveals processes hidden from `pslist`).
- Memory pages marked `PAGE_EXECUTE_READWRITE` (RWX) containing raw shellcode or unmapped PE headers.
