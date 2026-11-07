---
title: "Secure Coding: Input Validation, Normalization & Path Traversal"
tags: ["secure-coding", "input-validation", "path-traversal", "normalization", "cwe22"]
source: "OWASP Input Validation Cheat Sheet / CWE-22 (Path Traversal)"
---

# Secure Coding: Input Validation, Normalization & Path Traversal
## Source & Authority
OWASP Input Validation Cheat Sheet; Common Weakness Enumeration CWE-22 (Improper Limitation of a Pathname to a Restricted Directory).

## Path Traversal Defense
```python
import os
from pathlib import Path

def get_safe_file_path(base_dir: str, user_filename: str) -> Path:
    # Resolve absolute canonical paths
    base = Path(base_dir).resolve()
    target = (base / user_filename).resolve()
    # Enforce boundary check
    if not str(target).startswith(str(base) + os.sep):
        raise ValueError("Path traversal attempt detected")
    return target
```
- Validate input using strict allowlists (e.g. regex `^[a-zA-Z0-9_-]+\.pdf$`).
- Strip path separators (`/`, `\`) and null bytes (`\x00`).
