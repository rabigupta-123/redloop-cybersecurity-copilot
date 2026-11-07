---
title: "Digital Forensics Timeline Creation & Artifact Correlation"
tags: ["forensics", "timeline", "mft", "plaso", "incident-response"]
source: "NIST SP 800-86 / SANS Digital Forensics"
---

# Digital Forensics Timeline Creation & Artifact Correlation
## Source & Authority
NIST SP 800-86; SANS Investigative Forensics Framework.

## Timestamp Artifacts (MACB)
- **M (Modified):** File content last changed.
- **A (Accessed):** File read or executed.
- **C (Changed / MFT Modified):** File metadata or permissions altered.
- **B (Born / Created):** File initial creation timestamp.

## Anti-Forensic Detection (Timestomping)
Compare `$STANDARD_INFORMATION` (accessible to userland APIs, easily altered by timestomping utilities) with `$FILE_NAME` timestamps in the NTFS `$MFT` (modified only by the Windows kernel). A `$STANDARD_INFORMATION` timestamp earlier than the parent directory creation or `$FILE_NAME` indicates timestomping.
