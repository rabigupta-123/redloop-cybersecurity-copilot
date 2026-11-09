"""Untrusted tool output handling and prompt injection defense (Phase 2.2).

Guarantees:
1. Tool output is treated strictly as UNTRUSTED DATA and is never executed as instructions.
2. Identifies and flags prompt injection payloads attempting to override LLM system context.
3. Sanitizes dangerous control characters and script tags.
4. Redacts inadvertent API keys, tokens, or credentials appearing in tool outputs.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|jailbroken|evil|dan|new)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*override", re.IGNORECASE),
    re.compile(r"<\s*\|?im_start\|?>\s*system", re.IGNORECASE),
    re.compile(r"\[SYSTEM(?:\s+DIRECTIVE|\s+PROMPT)?\]", re.IGNORECASE),
    re.compile(r"BEGIN\s+(?:SYSTEM\s+)?INSTRUCTION", re.IGNORECASE),
    re.compile(r"developer\s+mode\s+enabled", re.IGNORECASE),
    re.compile(r"act\s+as\s+a\s+rogue\s+ai", re.IGNORECASE),
    re.compile(r"new\s+system\s+directive\s*:", re.IGNORECASE),
    re.compile(r"<script[\s\S]*?>[\s\S]*?<\/script>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
]

SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:api[_-]?key|secret|token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9_\-]{16,}", re.IGNORECASE),
    re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}", re.IGNORECASE),  # JWT
]


class UntrustedDataResult:
    def __init__(
        self,
        raw: str,
        sanitized: str,
        is_suspicious: bool,
        detected_patterns: List[str],
        secrets_redacted: int,
    ) -> None:
        self.raw = raw
        self.sanitized = sanitized
        self.is_suspicious = is_suspicious
        self.detected_patterns = detected_patterns
        self.secrets_redacted = secrets_redacted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized": self.sanitized,
            "is_suspicious": self.is_suspicious,
            "detected_patterns": self.detected_patterns,
            "secrets_redacted": self.secrets_redacted,
        }


def process_untrusted_output(raw_output: Any) -> UntrustedDataResult:
    """Sanitizes untrusted output from MCP tools or external APIs.
    
    Never raises an exception; always sanitizes and returns an UntrustedDataResult.
    """
    if raw_output is None:
        return UntrustedDataResult(raw="", sanitized="", is_suspicious=False, detected_patterns=[], secrets_redacted=0)

    if not isinstance(raw_output, str):
        try:
            import json
            text = json.dumps(raw_output, default=str)
        except Exception:
            text = str(raw_output)
    else:
        text = raw_output

    detected_patterns: List[str] = []
    sanitized = text

    # 1. Detect prompt injections
    for pattern in INJECTION_PATTERNS:
        matches = pattern.findall(sanitized)
        if matches:
            detected_patterns.append(pattern.pattern)
            # Defang pattern by replacing with safe placeholder
            sanitized = pattern.sub("[DEFANGED_INJECTION_PATTERN]", sanitized)

    is_suspicious = len(detected_patterns) > 0

    # 2. Redact sensitive secrets/tokens
    redacted_count = 0
    for pattern in SECRET_PATTERNS:
        matches = pattern.findall(sanitized)
        if matches:
            redacted_count += len(matches)
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

    # 3. Strip dangerous HTML/control tags
    sanitized = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "[REDACTED_SCRIPT]", sanitized, flags=re.DOTALL | re.IGNORECASE)
    sanitized = re.sub(r"on\w+\s*=", "data-defanged-event=", sanitized, flags=re.IGNORECASE)

    return UntrustedDataResult(
        raw=text,
        sanitized=sanitized,
        is_suspicious=is_suspicious,
        detected_patterns=detected_patterns,
        secrets_redacted=redacted_count,
    )
