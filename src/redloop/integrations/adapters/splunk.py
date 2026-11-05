"""Splunk Enterprise & Cloud SIEM Adapter (Phase 8).

Integrates with Splunk REST API (v9.x) for server health, bounded search job execution,
and alert retrieval with read-only SPL guardrails.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from redloop.assessment.soc_events import UniversalSecurityEvent
from redloop.integrations.base import (
    BaseProvider,
    HealthCheckResult,
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)
from redloop.integrations.config import IntegrationConfig
from redloop.integrations.credentials import mask_secret, sanitize_error_message
from redloop.integrations.normalizers import normalize_splunk_event

PERMITTED_READ_ONLY_SPL_COMMANDS = {
    "search", "where", "eval", "stats", "table", "fields", "dedup", "sort",
    "head", "tail", "rex", "lookup", "inputlookup", "rename", "timechart",
    "top", "rare", "chart", "strcat", "coalesce", "fillnull", "eventstats",
    "streamstats", "spath", "xmlkv", "kvform", "extract", "bin", "bucket",
    "iplocation", "geoip", "regex", "convert", "replace", "addinfo",
    "transaction", "concurrency", "cluster", "geom", "reverse", "makemv", "mvexpand",
}

PROHIBITED_SPL_COMMANDS = {
    "delete", "outputlookup", "outputcsv", "collect", "sendemail", "run", "script",
    "runshellscript", "makeresults", "dump", "rest", "snmp", "loadjob", "tscollect",
    "map", "inputcsv", "outputtext", "outputtelemetry", "crawl",
}


def validate_spl_query(spl_query: str, depth: int = 0, max_depth: int = 3, max_stages: int = 15) -> str:
    """Conservatively validates an SPL query for read-only compliance."""
    if not spl_query or not isinstance(spl_query, str):
        raise ValueError("SPL query must be a non-empty string.")

    if depth > max_depth:
        raise ValueError(f"Subsearch nesting exceeds maximum permitted depth of {max_depth}.")

    clean = spl_query.strip()
    if not clean:
        raise ValueError("SPL query cannot be empty.")
    if len(clean) > 2048:
        raise ValueError("SPL query exceeds maximum permitted length of 2048 characters.")

    # Reject statement termination / chaining
    if ";" in clean:
        raise ValueError("Command chaining or semicolon statement termination is prohibited in SPL.")

    # Reject backticks / macro invocations
    if "`" in clean:
        raise ValueError("Macro expansions and backtick syntax are prohibited in SPL search.")

    # Reject block comments or inline comments
    if "/*" in clean or "*/" in clean or clean.startswith("#") or "//" in clean:
        raise ValueError("Comments are prohibited in read-only SPL queries.")

    # Parse and validate subsearch bracket nesting
    current_depth = 0
    subsearches: list[tuple[int, int]] = []
    sub_start = -1
    for i, char in enumerate(clean):
        if char == "[":
            if current_depth == 0:
                sub_start = i
            current_depth += 1
            if depth + current_depth > max_depth:
                raise ValueError(f"Subsearch nesting exceeds maximum permitted depth of {max_depth}.")
        elif char == "]":
            current_depth -= 1
            if current_depth < 0:
                raise ValueError("Malformed SPL query: unmatched closing bracket.")
            if current_depth == 0 and sub_start != -1:
                subsearches.append((sub_start, i))
                sub_start = -1

    if current_depth != 0:
        raise ValueError("Malformed SPL query: unclosed bracket.")

    for start_idx, end_idx in subsearches:
        sub_content = clean[start_idx + 1:end_idx].strip()
        validate_spl_query(sub_content, depth=depth + 1, max_depth=max_depth, max_stages=max_stages)

    # Replace subsearch spans with spaces for top-level pipeline parsing
    pipeline_chars = list(clean)
    for start_idx, end_idx in subsearches:
        for k in range(start_idx, end_idx + 1):
            pipeline_chars[k] = " "
    pipeline_text = "".join(pipeline_chars)

    # Tokenize pipeline by pipe (|) outside of quotes
    stages = []
    current_token = []
    in_quote = False
    quote_char = None
    for char in pipeline_text:
        if char in ('"', "'"):
            if not in_quote:
                in_quote = True
                quote_char = char
            elif quote_char == char:
                in_quote = False
                quote_char = None
            current_token.append(char)
        elif char == "|" and not in_quote:
            stg = "".join(current_token).strip()
            if stg:
                stages.append(stg)
            current_token = []
        else:
            current_token.append(char)
    if in_quote:
        raise ValueError("Malformed SPL query: unbalanced quotes.")
    if current_token:
        stg = "".join(current_token).strip()
        if stg:
            stages.append(stg)

    if len(stages) > max_stages:
        raise ValueError(f"SPL query exceeds maximum pipeline stage limit of {max_stages} (found {len(stages)}).")

    for idx, stage in enumerate(stages):
        if not stage:
            continue
        words = stage.split()
        first_word = words[0].lower().strip("\"'()")

        # Check all tokens in stage for prohibited command injection
        for w in words:
            clean_w = w.lower().strip("\"'()")
            if clean_w in PROHIBITED_SPL_COMMANDS:
                raise ValueError(f"Prohibited non-read-only SPL command '{clean_w}' blocked.")

        # Handle implicit search in the first stage (e.g. "index=main error")
        if idx == 0 and ("=" in first_word or first_word.startswith("(") or first_word not in PERMITTED_READ_ONLY_SPL_COMMANDS):
            continue

        if first_word in PROHIBITED_SPL_COMMANDS:
            raise ValueError(f"Prohibited non-read-only SPL command '{first_word}' blocked.")

        if first_word not in PERMITTED_READ_ONLY_SPL_COMMANDS:
            raise ValueError(f"Unrecognized or unapproved SPL command '{first_word}' blocked by read-only policy.")

        # Validate and bound head or limit argument values (max 10000)
        if first_word in ("head", "limit"):
            for w in words[1:]:
                cw = w.lower().strip("\"'()")
                if cw.isdigit():
                    val = int(cw)
                    if val > 10000:
                        raise ValueError(f"SPL {first_word} count {val} exceeds maximum allowed limit of 10000.")
                elif cw.startswith("limit=") or cw.startswith("count=") or cw.startswith("n="):
                    part = cw.split("=", 1)[1].strip("\"'()")
                    if part.isdigit() and int(part) > 10000:
                        raise ValueError(f"SPL {first_word} count {part} exceeds maximum allowed limit of 10000.")

    return clean


class SplunkAdapter(BaseProvider):
    """Adapter for Splunk REST API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 8089,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="splunk",
            display_name="Splunk Enterprise / Cloud SIEM",
            category=ProviderCategory.SIEM,
            version="9.2.0",
            enabled=enabled,
        )
        self._explicit_host = host
        self._port = port
        self._explicit_token = token
        self._explicit_username = username
        self._explicit_password = password

        self._capabilities = {
            ProviderCapability.READ_ALERTS,
            ProviderCapability.SEARCH_EVENTS,
        }

    @property
    def host(self) -> Optional[str]:
        return self._explicit_host or IntegrationConfig.get_setting("splunk", "host") or IntegrationConfig.get_setting("splunk", "url")

    @property
    def port(self) -> int:
        p_str = IntegrationConfig.get_setting("splunk", "port")
        if p_str:
            try:
                return int(p_str)
            except ValueError:
                pass
        return self._port

    @property
    def token(self) -> Optional[str]:
        return self._explicit_token or IntegrationConfig.get_setting("splunk", "token")

    @property
    def username(self) -> Optional[str]:
        return self._explicit_username or IntegrationConfig.get_setting("splunk", "username") or IntegrationConfig.get_setting("splunk", "user")

    @property
    def password(self) -> Optional[str]:
        return self._explicit_password or IntegrationConfig.get_setting("splunk", "password")

    @property
    def base_url(self) -> Optional[str]:
        if not self.host:
            return None
        h = self.host.rstrip("/")
        if not h.startswith("http://") and not h.startswith("https://"):
            h = f"https://{h}:{self.port}"
        elif ":" not in h.replace("http://", "").replace("https://", ""):
            h = f"{h}:{self.port}"
        return h

    def is_configured(self) -> bool:
        if not self.host:
            return False
        return bool(self.token or (self.username and self.password))

    def get_public_config(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "token": mask_secret(self.token),
            "username": self.username,
            "password": mask_secret(self.password),
        }

    def _get_headers(self) -> dict[str, str]:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Splunk {self.token}"
        elif self.username and self.password:
            creds = f"{self.username}:{self.password}".encode("utf-8")
            b64_creds = base64.b64encode(creds).decode("utf-8")
            headers["Authorization"] = f"Basic {b64_creds}"
        return headers

    def test_connection(self) -> HealthCheckResult:
        """Executes connection health probe against Splunk server info endpoint."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Splunk is not configured. Supply SPLUNK_HOST and SPLUNK_TOKEN (or USER/PASSWORD).",
            )
            self._last_health = res
            return res

        start = time.time()
        try:
            url = f"{self.base_url}/services/server/info?output_mode=json"
            req = urllib.request.Request(url, headers=self._get_headers())
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    entry = data.get("entry", [{}])[0].get("content", {})
                    server_name = entry.get("serverName", "splunk")
                    version = entry.get("version", "9.x")
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message=f"Connected to Splunk server '{server_name}' (v{version}).",
                        details={"server_name": server_name, "version": version},
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Splunk returned HTTP {resp.status}.",
                    )
        except urllib.error.HTTPError as he:
            elapsed = (time.time() - start) * 1000.0
            st = ProviderStatus.AUTH_FAILED if he.code in (401, 403) else ProviderStatus.ERROR
            res = HealthCheckResult(
                status=st,
                latency_ms=round(elapsed, 2),
                message=f"HTTP {he.code}: Splunk authentication failed.",
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.UNAVAILABLE,
                latency_ms=round(elapsed, 2),
                message=sanitize_error_message(f"Connection failed: {str(e)}"),
            )

        return self.record_health(res)

    def search_events(
        self,
        spl_query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        limit: int = 50,
    ) -> list[UniversalSecurityEvent]:
        """Executes a bounded, read-only SPL search job."""
        if not self.is_configured():
            return []

        # Validate SPL query with conservative read-only policy
        safe_spl = validate_spl_query(spl_query)

        # Validate time boundaries
        time_pattern = r"^(-[0-9]+[smhdwMy]|now|0|\d{4}-\d{2}-\d{2}.*|\d+)$"
        if not re.match(time_pattern, earliest_time.strip()):
            raise ValueError(f"Invalid Splunk search earliest_time boundary '{earliest_time}'.")
        if not re.match(time_pattern, latest_time.strip()):
            raise ValueError(f"Invalid Splunk search latest_time boundary '{latest_time}'.")

        bounded_limit = min(max(1, limit), 1000)
        if not safe_spl.startswith("search") and not safe_spl.startswith("|"):
            safe_spl = f"search {safe_spl}"
        if "| head" not in safe_spl:
            safe_spl = f"{safe_spl} | head {bounded_limit}"

        # 1. Create Search Job
        job_url = f"{self.base_url}/services/search/jobs?output_mode=json"
        job_data = urllib.parse.urlencode({
            "search": safe_spl,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "exec_mode": "oneshot",
        }).encode("utf-8")

        headers = self._get_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        try:
            req = urllib.request.Request(job_url, data=job_data, headers=headers)
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                return [normalize_splunk_event(r, provider_id=self.provider_id) for r in results]
        except Exception:
            return []
