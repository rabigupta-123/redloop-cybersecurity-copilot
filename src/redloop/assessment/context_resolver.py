"""Request-Scoped Context Structure and Explicit Target Resolution Architecture.

Enforces strict per-request target precedence, entity/task-type validation,
and cross-task context isolation:
1. Explicit target supplied in current user request.
2. Explicit target supplied in current task's structured input.
3. Target explicitly selected for current active investigation.
4. If none exists, request clarification when required (never silently substitute 127.0.0.1 or stale targets).
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RequestContext:
    """Request-scoped execution context separating task context from investigation context."""

    request_id: str = field(default_factory=lambda: f"req-{uuid.uuid4().hex[:12]}")
    task_id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")
    user_message: str = ""
    task_type: str = "general_chat"
    explicit_target: str | None = None
    target_type: str = "none"  # ip, cidr, domain, email, url, none, unknown
    active_investigation_id: str | None = None
    selected_tools: list[str] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    execution_status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, BLOCKED, CLARIFICATION_REQUIRED

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TargetResolver:
    """Deterministic entity extractor and 4-tier precedence resolver."""

    FILE_EXTENSIONS = {
        ".py", ".js", ".json", ".yaml", ".yml", ".txt", ".log", ".md",
        ".png", ".jpg", ".jpeg", ".gif", ".sh", ".c", ".cpp", ".h",
        ".html", ".css", ".sql", ".sqlite", ".db", ".tar", ".gz", ".zip",
    }

    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
    URL_PATTERN = re.compile(r"\bhttps?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
    DOMAIN_PATTERN = re.compile(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(?:\.(?:[a-zA-Z]{2,}|local|internal|corp|lan)))\b",
        re.IGNORECASE,
    )

    @classmethod
    def classify_target(cls, target: str | None) -> tuple[str, str | None]:
        """Classify a target string into (target_type, cleaned_target)."""
        if not target or not target.strip():
            return "none", None
        t = target.strip()

        # 0. Strip surrounding quotes and backticks: "'handle'" -> "handle"
        t_unquoted = t.strip("'\"`").strip()

        # 0.1 Check platform prefix: e.g. "on GitHub: shadow_broker", "github: shadow_broker", "handle: shadow_broker"
        plat_match = re.match(
            r"^(?:on\s+)?(?:github|gitlab|twitter|x|reddit|discord|telegram|linkedin|instagram|keybase|medium|hackerone|bugcrowd|user|handle|username|alias|nickname|operator)\s*[:=\s]\s*['\"`]?([@a-zA-Z0-9_\-\.]+)",
            t_unquoted,
            re.IGNORECASE,
        )
        if plat_match:
            cand = plat_match.group(1).lstrip("@").strip("'\"`").rstrip(".,;:!?")
            if not cls.DOMAIN_PATTERN.fullmatch(cand):
                return "username", cand

        # 0.2 Check @-prefixed handle: e.g. "@shadow_broker"
        if t_unquoted.startswith("@") and len(t_unquoted) > 1:
            cand = t_unquoted.lstrip("@").strip()
            if re.fullmatch(r"[a-zA-Z0-9_\-\.]{2,32}", cand) and not cls.DOMAIN_PATTERN.fullmatch(cand):
                return "username", cand

        # Update working target to unquoted string
        t = t_unquoted

        # 1. URL Check
        if t.lower().startswith(("http://", "https://")):
            return "url", t

        # 2. Email Check
        if cls.EMAIL_PATTERN.fullmatch(t):
            return "email", t.lower()

        # 3. IP / CIDR Check
        try:
            if "/" in t:
                ipaddress.ip_network(t, strict=False)
                return "cidr", t
            else:
                ipaddress.ip_address(t)
                return "ip", t
        except ValueError:
            pass

        # 4. Localhost Special Case
        if t.lower() in ("localhost", "127.0.0.1"):
            return ("domain" if t.lower() == "localhost" else "ip"), t.lower()

        # Check Phone
        if re.fullmatch(r"(?:\+|00)[0-9\s\-\(\)\.]{7,22}", t) or re.fullmatch(r"\+?1?[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}", t):
            return "phone", t

        # 5. Exclude file names from domains, except known domain TLDs
        if any(t.lower().endswith(ext) for ext in cls.FILE_EXTENSIONS) and not t.lower().endswith(".sh"):
            return "unknown", t

        # 6. Domain Check (must precede general username check)
        if cls.DOMAIN_PATTERN.fullmatch(t):
            return "domain", t.lower()

        # Check Username: 2-32 chars alphanumeric with underscores/hyphens/dots
        STOPWORDS = {"with", "from", "for", "the", "this", "that", "into", "onto", "scan", "check", "assess", "probe", "nmap", "and", "or", "not", "test", "host", "target", "authorized", "ip", "address", "domain"}
        if t.lower() not in STOPWORDS and re.fullmatch(r"[a-zA-Z0-9_\-\.]{2,32}", t):
            return "username", t

        return "unknown", t

    @classmethod
    def extract_prompt_target(cls, prompt: str) -> tuple[str | None, str]:
        """Extract explicit target indicator from natural language prompt."""
        if not prompt or not prompt.strip():
            return None, "none"
        p_lower = prompt.lower().strip()
        STOPWORDS = {"with", "from", "for", "the", "this", "that", "into", "onto", "scan", "check", "assess", "probe", "nmap", "and", "or", "not", "test", "host", "target", "authorized", "ip", "address", "domain", "accounts", "public", "online", "profiles", "active", "open", "source", "associations", "reconnaissance"}

        # 1. Quoted handle/username tokens when user/handle/account/osint context keywords are present
        if any(w in p_lower for w in ("username", "handle", "user", "operator", "alias", "nickname", "social", "profile", "account", "forum", "footprint", "identity", "repositories", "commits")):
            q_matches = re.findall(r"['\"`]([a-zA-Z0-9_\-\.]{2,32})['\"`]", prompt)
            for q_cand in q_matches:
                q_clean = q_cand.lstrip("@").strip()
                if q_clean.lower() not in STOPWORDS and not cls.DOMAIN_PATTERN.fullmatch(q_clean):
                    try:
                        ipaddress.ip_address(q_clean)
                    except ValueError:
                        return q_clean, "username"

        # 2. Explicit key-value patterns: username: xyz, handle: xyz, alias: xyz, --username xyz
        user_kw = re.search(
            r"\b(?:--username\b|-u\b|username:?|handle:?|alias:?|nickname:?|operator:?)\s*[:=\s]\s*['\"`]?([@a-zA-Z0-9_\-\.]{2,32})['\"`]?",
            prompt,
            re.IGNORECASE,
        )
        if user_kw:
            u_cand = user_kw.group(1).lstrip("@").strip("'\"`").rstrip(".,;:!?")
            if u_cand.lower() not in STOPWORDS and not cls.DOMAIN_PATTERN.fullmatch(u_cand):
                return u_cand, "username"

        # 3. Platform prefix: "on GitHub: shadow_broker", "Twitter: shadow_coder", "Reddit: @stealth"
        plat_match = re.search(
            r"\b(?:on\s+)?(?:github|gitlab|twitter|x|reddit|discord|telegram|linkedin|instagram|keybase|medium|hackerone|bugcrowd)\s*[:=\s]\s*['\"`]?([@a-zA-Z0-9_\-\.]{2,32})['\"`]?",
            prompt,
            re.IGNORECASE,
        )
        if plat_match:
            cand = plat_match.group(1).lstrip("@").strip("'\"`").rstrip(".,;:!?")
            if cand.lower() not in STOPWORDS and not cls.DOMAIN_PATTERN.fullmatch(cand):
                return cand, "username"

        # 4. Standalone @handle: e.g. "@shadow_broker"
        at_match = re.search(r"(?<!\w)@([a-zA-Z0-9_\-\.]{2,32})\b", prompt)
        if at_match:
            at_cand = at_match.group(1)
            if not cls.DOMAIN_PATTERN.fullmatch(at_cand):
                return at_cand, "username"

        # 5. Explicit target patterns: target: xyz, on xyz, for xyz, target=xyz
        kw_match = re.search(
            r"\b(?:--target\b|-t\b|target:?|host:|domain:|ip:|url:|email:)\s+(?:ip\s+|address\s+|host\s+|domain\s+)?([^\s,;]+)",
            prompt,
            re.IGNORECASE,
        )
        if kw_match:
            candidate = kw_match.group(1).strip().strip("'\"").rstrip(".,;:!?")
            c_type, c_val = cls.classify_target(candidate)
            if c_type != "unknown" and c_val:
                return c_val, c_type

        # Check for URL
        url_match = cls.URL_PATTERN.search(prompt)
        if url_match:
            u = url_match.group(0).rstrip(".,;!?'\")")
            return u, "url"

        # Check for Email
        email_match = cls.EMAIL_PATTERN.search(prompt)
        if email_match:
            return email_match.group(0).lower(), "email"

        # Check for IP / CIDR
        for m in cls.IPV4_PATTERN.finditer(prompt):
            cand = m.group(0)
            try:
                if "/" in cand:
                    ipaddress.ip_network(cand, strict=False)
                    return cand, "cidr"
                else:
                    ipaddress.ip_address(cand)
                    return cand, "ip"
            except ValueError:
                continue

        # Check for Localhost / Loopback
        loc_match = re.search(r"\b(localhost|127\.0\.0\.1)\b", prompt, re.IGNORECASE)
        if loc_match:
            return "127.0.0.1", "ip"

        # Check for Phone Number
        phone_cand = re.search(r"(?:\+|00)[1-9][0-9\s\-\(\)\.]{5,18}\d", prompt) or re.search(r"\b\+?1[-. ]?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b", prompt)
        if phone_cand and any(w in prompt.lower() for w in ("phone", "number", "carrier", "country code", "lookup phone")):
            return phone_cand.group(0).strip(), "phone"

        # Check for Domain
        for m in cls.DOMAIN_PATTERN.finditer(prompt):
            cand = m.group(1).rstrip(".,;!?'\")")
            c_type, c_val = cls.classify_target(cand)
            if c_type == "domain" and c_val:
                return c_val, "domain"

        return None, "none"

    @classmethod
    def resolve_target(
        cls,
        prompt: str,
        context: dict[str, Any] | None = None,
        task_requires_target: bool = False,
    ) -> tuple[str | None, str, str]:
        """Resolve target based on strict 4-tier precedence:

        1. Explicit target supplied in current user request.
        2. Explicit target supplied in current task's structured input.
        3. Target explicitly selected by the user for current investigation.
        4. None (clarification requested when task requires target; no silent substitutions).

        Returns: (target_value, target_type, resolution_source)
        """
        ctx = context or {}

        # 1. Explicit target supplied in current user request (prompt)
        prompt_target, prompt_type = cls.extract_prompt_target(prompt)
        if prompt_target:
            return prompt_target, prompt_type, "prompt"

        # 2. Explicit target supplied in current task's structured input
        structured_target = ctx.get("explicit_target") or ctx.get("task_target")
        if structured_target and isinstance(structured_target, str) and structured_target.strip():
            s_type, s_val = cls.classify_target(structured_target.strip())
            if s_val:
                return s_val, s_type, "structured"

        # 3. Target explicitly selected for current active investigation
        inv_target = ctx.get("investigation_target")
        if not inv_target and ctx.get("active_investigation_id") and ctx.get("target"):
            inv_target = ctx.get("target")

        if inv_target and isinstance(inv_target, str) and inv_target.strip():
            i_type, i_val = cls.classify_target(inv_target.strip())
            if i_val:
                return i_val, i_type, "investigation"

        # 4. None - Never silently substitute 127.0.0.1 or previous targets!
        return None, "none", "none"

    @classmethod
    def validate_tool_target(
        cls,
        action: str,
        target: str | None,
        target_type: str,
    ) -> tuple[bool, str | None]:
        """Validate target type suitability for specific cybersecurity tools and actions."""
        # Actions that do NOT require a target
        NO_TARGET_ACTIONS = {
            "general_chat",
            "coding_and_research",
            "tool_detection",
            "audit_verify",
            "ctf_analysis",
            "ctf_codec",
            "forensics_analysis",
            "terminal_analysis",
            "graph_investigation",
            "follow_up_investigation",
            "kali_copilot",
            "kali_execute",
            "report_generate",
            "file_metadata_analysis",
            "explain_finding",
            "explain_evidence",
            "explain_attack_surface",
            "lifecycle_pause",
            "lifecycle_resume",
            "lifecycle_cancel",
        }
        if action in NO_TARGET_ACTIONS:
            return True, None

        if not target or target_type == "none":
            return False, f"Missing target: A target is required to execute '{action}'. Please provide a valid host, IP, domain, or URL."

        # Action-specific type requirements
        if action == "osint_ip":
            if target_type not in ("ip", "cidr"):
                return False, f"Target type mismatch: IP intelligence requires an IPv4 or IPv6 address, but received {target_type} target '{target}'. Use the appropriate OSINT module instead."
            return True, None

        if action == "osint_domain":
            if target_type != "domain":
                return False, f"Target type mismatch: Domain intelligence requires a valid domain or hostname, but received {target_type} target '{target}'. Use IP intelligence for IP addresses."
            return True, None

        if action == "osint_email":
            if target_type != "email":
                return False, f"Target type mismatch: Email intelligence requires a valid email address (e.g. user@example.com), but received {target_type} target '{target}'. IP addresses and domains cannot be queried as email accounts."
            return True, None

        if action == "osint_phone":
            if target_type not in ("phone", "unknown"):
                return False, f"Target type mismatch: Phone intelligence requires a phone number, but received {target_type} target '{target}'."
            return True, None

        if action == "osint_username":
            return True, None

        if action in ("tool_ports", "tool_nmap"):
            if target_type in ("email",):
                return False, f"Target type mismatch: Port scanning requires an IP address, CIDR network, or domain/hostname, but received email address '{target}'."
            if target_type not in ("ip", "cidr", "domain", "url"):
                return False, f"Invalid target for port scanning: '{target}'."
            return True, None

        if action in ("tool_tls", "tool_web", "tool_nikto", "tool_gobuster", "tool_api"):
            if target_type in ("email",):
                return False, f"Target type mismatch: Web/TLS tools require a URL, domain, or IP address, but received email address '{target}'."
            if target_type not in ("domain", "ip", "url", "cidr"):
                return False, f"Invalid target for {action}: '{target}'."
            return True, None

        if action == "run_assessment":
            if target_type in ("email",):
                return False, f"Target type mismatch: Vulnerability assessments require a host, IP, CIDR, or domain, but received email address '{target}'."
            return True, None

        return True, None

