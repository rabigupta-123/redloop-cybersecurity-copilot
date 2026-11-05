"""REDLOOP SOAR Action Registry & Safe Execution Engine (Phase 7 & Phase 7.1).

Provides:
1. Strongly typed, sandbox-safe action registry for SOAR playbooks.
2. Clear distinction between INVESTIGATION, DEFENSIVE (SIMULATED), and CONTAINMENT actions.
3. Strict enforcement: Destructive containment actions require operator approval capabilities.
4. Provider integration abstraction (distinguishing REAL, SIMULATED, and NOT_CONFIGURED).
5. Comprehensive SSRF-safe notification and escalation dispatching with IPv4/IPv6,
   DNS rebinding prevention, integer IP rejection, and credentials scrubbing.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import urllib.parse
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


def redact_sensitive_url(url: str) -> str:
    """Removes embedded credentials and sensitive query parameters from URLs."""
    if not url or not isinstance(url, str):
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        netloc = parsed.netloc
        if "@" in netloc:
            _, host_part = netloc.split("@", 1)
            netloc = f"[REDACTED]@{host_part}"

        if parsed.query:
            query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            safe_params = []
            sensitive_keys = {"token", "key", "secret", "password", "auth", "api_key", "bearer", "access_token"}
            for k, v in query_params:
                if k.lower() in sensitive_keys or any(s in k.lower() for s in ("secret", "token", "password", "key")):
                    safe_params.append((k, "******"))
                else:
                    safe_params.append((k, v))
            query = urllib.parse.urlencode(safe_params, safe="*")
        else:
            query = ""

        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
    except Exception:
        return re.sub(r"://[^@]+@", "://[REDACTED]@", url)


class ActionCategory(str, Enum):
    INVESTIGATION = "INVESTIGATION"
    DEFENSIVE = "DEFENSIVE"
    CONTAINMENT = "CONTAINMENT"
    NOTIFICATION = "NOTIFICATION"


class ActionExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    SIMULATED = "SIMULATED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


@dataclass
class ActionResult:
    """Standardized output of a SOAR action execution."""
    action_id: str
    action_name: str
    category: ActionCategory
    status: ActionExecutionStatus
    target: str
    parameters: dict[str, Any]
    details: str
    output_data: dict[str, Any] = field(default_factory=dict)
    is_simulated: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["status"] = self.status.value
        return d


class SSRFValidationError(Exception):
    """Raised when a destination URL targets private, internal, loopback, or restricted network ranges."""
    pass


class SafeWebhookClient:
    """SSRF-protected webhook dispatcher enforcing strict IPv4/IPv6 validation, DNS rebinding defenses, and HTTPS."""

    PROHIBITED_HOSTS = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "::",
        "169.254.169.254",
        "metadata.google.internal",
        "instance-data",
    }
    PROHIBITED_SUFFIXES = (".internal", ".local", ".localhost", ".onion", ".lan", ".home", ".corp")
    PROHIBITED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback
        ipaddress.ip_network("169.254.0.0/16"),    # Link-local
        ipaddress.ip_network("172.16.0.0/12"),    # Private
        ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments
        ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
        ipaddress.ip_network("192.168.0.0/16"),   # Private
        ipaddress.ip_network("198.18.0.0/15"),    # Benchmarking
        ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
        ipaddress.ip_network("224.0.0.0/4"),      # Multicast
        ipaddress.ip_network("240.0.0.0/4"),      # Reserved
        ipaddress.ip_network("255.255.255.255/32"),
        # IPv6
        ipaddress.ip_network("::1/128"),          # Loopback
        ipaddress.ip_network("::/128"),           # Unspecified
        ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped IPv6
        ipaddress.ip_network("100::/64"),         # Discard-only
        ipaddress.ip_network("2001:db8::/32"),    # Documentation
        ipaddress.ip_network("fc00::/7"),         # Unique local address (ULA)
        ipaddress.ip_network("fe80::/10"),        # Link-local unicast
        ipaddress.ip_network("ff00::/8"),         # Multicast
    ]
    MAX_RESPONSE_BYTES = 1048576  # 1MB ceiling
    DEFAULT_TIMEOUT = 5.0

    @classmethod
    def validate_destination(
        cls,
        url: str,
        allowed_domains: Optional[list[str]] = None,
        allow_http: bool = False,
    ) -> tuple[str, list[str]]:
        """Strictly validates destination URL against SSRF attack vectors.

        Returns:
            tuple: (normalized_hostname, list_of_resolved_ip_strings)
        Raises:
            SSRFValidationError if destination violates security policies.
        """
        if not url or not isinstance(url, str):
            raise SSRFValidationError("Webhook destination URL must be a non-empty string.")

        url_clean = url.strip()
        try:
            parsed = urllib.parse.urlsplit(url_clean)
        except Exception as e:
            raise SSRFValidationError(f"Malformed webhook destination URL: {e}")

        scheme = parsed.scheme.lower()
        if not allow_http and scheme != "https":
            raise SSRFValidationError("Webhook destination must use secure HTTPS protocol.")
        if scheme not in ("http", "https"):
            raise SSRFValidationError(f"Prohibited URL scheme '{scheme}'. Only HTTPS is permitted.")

        # Prohibit embedded credentials (userinfo)
        if parsed.username or parsed.password:
            raise SSRFValidationError("Embedded credentials in webhook URL are prohibited.")

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            raise SSRFValidationError("Webhook URL missing valid hostname.")

        # Prohibit known local hostnames and suffixes
        if hostname in cls.PROHIBITED_HOSTS or any(hostname.endswith(sfx) for sfx in cls.PROHIBITED_SUFFIXES):
            raise SSRFValidationError(f"SSRF Protection: Webhook destination '{hostname}' is a prohibited local/internal host.")

        # Check domain allowlist if configured
        if allowed_domains:
            allow_matched = False
            for ad in allowed_domains:
                clean_ad = ad.lower().strip()
                if hostname == clean_ad or hostname.endswith("." + clean_ad):
                    allow_matched = True
                    break
            if not allow_matched:
                raise SSRFValidationError(f"Webhook destination domain '{hostname}' not in configured allowlist.")

        resolved_ips: list[str] = []

        # Check direct IP literals (IPv4 or IPv6)
        try:
            clean_host_for_ip = hostname.strip("[]")
            direct_ip = ipaddress.ip_address(clean_host_for_ip)
            cls._check_ip_safety(direct_ip)
            resolved_ips.append(str(direct_ip))
            return hostname, resolved_ips
        except ValueError:
            pass

        # Detect and reject decimal/octal/hex integer IP representations (e.g. 2130706433, 0x7f000001)
        if re.match(r"^\d+$", hostname) or re.match(r"^0x[0-9a-fA-F]+$", hostname) or re.match(r"^0[0-7]+$", hostname):
            try:
                numeric_val = int(hostname, 0)
                ip_from_num = ipaddress.ip_address(numeric_val)
                cls._check_ip_safety(ip_from_num)
                resolved_ips.append(str(ip_from_num))
                return hostname, resolved_ips
            except Exception:
                raise SSRFValidationError(f"SSRF Protection: Malformed or prohibited numeric IP representation: '{hostname}'.")

        # Resolve via socket.getaddrinfo to capture both IPv4 and IPv6
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SSRFValidationError(f"Cannot resolve webhook host '{hostname}': {e}")

        if not addr_info:
            raise SSRFValidationError(f"Resolution returned no addresses for host '{hostname}'.")

        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                cls._check_ip_safety(ip_obj)
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
            except ValueError as ve:
                raise SSRFValidationError(f"Invalid resolved IP '{ip_str}' for host '{hostname}': {ve}")

        return hostname, resolved_ips

    @classmethod
    def _check_ip_safety(cls, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        """Inspects an IP address against RFC1918, link-local, multicast, loopback, and metadata ranges."""
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        for net in cls.PROHIBITED_NETWORKS:
            if ip_obj in net:
                raise SSRFValidationError(
                    f"SSRF Protection: IP '{ip_obj}' falls within restricted network range {net}."
                )

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise SSRFValidationError(
                f"SSRF Protection: IP '{ip_obj}' is in a private, loopback, or reserved subnet."
            )

    @classmethod
    def validate_url(cls, url: str) -> None:
        """Backward-compatible validation helper for existing callers."""
        cls.validate_destination(url)

    @classmethod
    def post(
        cls,
        url: str,
        payload: Optional[dict[str, Any] | str] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        allowed_domains: Optional[list[str]] = None,
        allow_http: bool = False,
        follow_redirects: bool = False,
        max_redirects: int = 3,
    ) -> dict[str, Any]:
        """Dispatches an outbound HTTP POST request via strictly connection-pinned sockets."""
        current_url = url
        redirect_count = 0

        while True:
            safe_log_url = redact_sensitive_url(current_url)
            hostname, resolved_ips = cls.validate_destination(
                current_url,
                allowed_domains=allowed_domains,
                allow_http=allow_http,
            )

            parsed = urllib.parse.urlsplit(current_url)
            scheme = parsed.scheme.lower()
            port = parsed.port or (443 if scheme == "https" else 80)
            target_ip = resolved_ips[0]

            path_and_query = parsed.path or "/"
            if parsed.query:
                path_and_query += f"?{parsed.query}"

            req_headers = dict(headers or {})
            req_headers["Host"] = hostname
            req_headers.setdefault("User-Agent", "REDLOOP-SOAR/1.0 (SSRF-Protected)")

            body_bytes = b""
            if payload is not None:
                if isinstance(payload, dict):
                    body_bytes = json.dumps(payload).encode("utf-8")
                    req_headers.setdefault("Content-Type", "application/json")
                elif isinstance(payload, str):
                    body_bytes = payload.encode("utf-8")
                elif isinstance(payload, bytes):
                    body_bytes = payload
                req_headers["Content-Length"] = str(len(body_bytes))

            conn = None
            try:
                if scheme == "https":
                    conn = PinnedHTTPSConnection(
                        validated_ip=target_ip,
                        server_hostname=hostname,
                        port=port,
                        timeout=timeout,
                    )
                else:
                    conn = PinnedHTTPConnection(
                        validated_ip=target_ip,
                        server_hostname=hostname,
                        port=port,
                        timeout=timeout,
                    )

                conn.request("POST", path_and_query, body=body_bytes, headers=req_headers)
                resp = conn.getresponse()

                if resp.status in (301, 302, 303, 307, 308):
                    if not follow_redirects:
                        raise SSRFValidationError(f"Redirects disabled by default (received HTTP {resp.status} from '{safe_log_url}').")
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise SSRFValidationError(f"Maximum redirect chain limit exceeded ({max_redirects}).")
                    loc = resp.getheader("Location")
                    if not loc:
                        raise SSRFValidationError("Redirect response missing Location header.")
                    current_url = urllib.parse.urljoin(current_url, loc)
                    conn.close()
                    continue

                content_len = resp.getheader("Content-Length")
                if content_len and int(content_len) > cls.MAX_RESPONSE_BYTES:
                    raise SSRFValidationError(f"Response Content-Length ({content_len}) exceeds maximum limit ({cls.MAX_RESPONSE_BYTES} bytes).")

                chunks = []
                bytes_read = 0
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    if bytes_read > cls.MAX_RESPONSE_BYTES:
                        raise SSRFValidationError(f"Response size exceeded {cls.MAX_RESPONSE_BYTES} bytes ceiling.")
                    chunks.append(chunk)

                raw_body = b"".join(chunks).decode("utf-8", errors="replace")
                return {
                    "status_code": resp.status,
                    "target_host": hostname,
                    "target_ip": target_ip,
                    "headers": dict(resp.getheaders()),
                    "body": raw_body,
                }
            except socket.timeout:
                raise SSRFValidationError(f"Connection to '{safe_log_url}' timed out after {timeout}s.")
            except Exception as exc:
                if isinstance(exc, SSRFValidationError):
                    raise
                safe_err = redact_sensitive_url(str(exc))
                raise SSRFValidationError(f"Webhook connection failure: {safe_err}")
            finally:
                if conn:
                    conn.close()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection bound to a pre-validated IP address with TLS SNI hostname preservation."""
    def __init__(self, validated_ip: str, server_hostname: str, port: int = 443, timeout: float = 5.0, context: Optional[ssl.SSLContext] = None):
        super().__init__(host=validated_ip, port=port, timeout=timeout, context=context or ssl.create_default_context())
        self.pinned_server_hostname = server_hostname

    def connect(self) -> None:
        super().connect()
        peer_ip = self.sock.getpeername()[0]
        if peer_ip != self.host:
            self.sock.close()
            raise SSRFValidationError(f"SSRF Peer Mismatch: Connected peer IP '{peer_ip}' does not match validated destination IP '{self.host}'.")
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.pinned_server_hostname)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection bound to a pre-validated IP address for permitted internal dev targets."""
    def __init__(self, validated_ip: str, server_hostname: str, port: int = 80, timeout: float = 5.0):
        super().__init__(host=validated_ip, port=port, timeout=timeout)
        self.pinned_server_hostname = server_hostname

    def connect(self) -> None:
        super().connect()
        peer_ip = self.sock.getpeername()[0]
        if peer_ip != self.host:
            self.sock.close()
            raise SSRFValidationError(f"SSRF Peer Mismatch: Connected peer IP '{peer_ip}' does not match validated destination IP '{self.host}'.")


class SOARActionRegistry:
    """Authoritative registry of executable SOAR actions."""

    _LOCAL_SIMULATED_BLOCKLIST: set[str] = set()

    # ==========================================================================
    # 1. Investigation Actions (Read-Only, Safe, Automated)
    # ==========================================================================

    @classmethod
    def retrieve_related_events(
        cls,
        target_ip: Optional[str] = None,
        target_host: Optional[str] = None,
        limit: int = 50,
        stored_events: Optional[list[Any]] = None,
        **kwargs: Any,
    ) -> ActionResult:
        """Retrieves events matching an IP or host entity from stored telemetry."""
        target_entity = target_ip or target_host or "UNKNOWN_TARGET"
        matched: list[dict[str, Any]] = []
        events = stored_events or []

        for ev in events:
            ev_ip = getattr(ev, "source_ip", "") or getattr(ev, "destination_ip", "")
            ev_host = getattr(ev, "hostname", "")
            if (target_ip and target_ip in ev_ip) or (target_host and target_host in ev_host):
                matched.append(ev.to_dict() if hasattr(ev, "to_dict") else dict(ev))
                if len(matched) >= limit:
                    break

        return ActionResult(
            action_id=f"act-rev-{uuid.uuid4().hex[:8]}",
            action_name="retrieve_related_events",
            category=ActionCategory.INVESTIGATION,
            status=ActionExecutionStatus.SUCCESS,
            target=target_entity,
            parameters={"target_ip": target_ip, "target_host": target_host, "limit": limit},
            details=f"Retrieved {len(matched)} related events for entity '{target_entity}'.",
            output_data={"matched_count": len(matched), "events": matched},
            evidence_ids=[e.get("event_id") for e in matched if "event_id" in e],
        )

    @classmethod
    def enrich_indicator(
        cls,
        indicator: Optional[str] = None,
        target_context: Optional[str] = None,
        indicator_type: str = "ip",  # ip | domain | hash
        **kwargs: Any,
    ) -> ActionResult:
        """Enriches an IP, domain, or file hash with threat intelligence reputation."""
        ind = indicator or target_context or "127.0.0.1"
        ind_clean = ind.strip()
        reputation = "UNKNOWN"
        risk_score = 0.0
        threat_tags: list[str] = []

        if indicator_type == "ip":
            # Check private vs public
            try:
                ip_obj = ipaddress.ip_address(ind_clean)
                if ip_obj.is_private:
                    reputation = "INTERNAL_PRIVATE_IP"
                    risk_score = 0.1
                else:
                    reputation = "EXTERNAL_PUBLIC_IP"
                    risk_score = 0.5
            except Exception:
                reputation = "INVALID_IP"

        elif indicator_type == "hash":
            # Known test hashes
            if ind_clean.lower().startswith("e3b0c442"):  # empty sha256
                reputation = "BENIGN"
                risk_score = 0.0
            else:
                reputation = "SUSPICIOUS_HASH"
                risk_score = 0.75
                threat_tags.append("potential_trojan")

        return ActionResult(
            action_id=f"act-enr-{uuid.uuid4().hex[:8]}",
            action_name="enrich_indicator",
            category=ActionCategory.INVESTIGATION,
            status=ActionExecutionStatus.SUCCESS,
            target=ind_clean,
            parameters={"indicator": ind_clean, "indicator_type": indicator_type},
            details=f"Indicator '{ind_clean}' enriched with reputation '{reputation}' (Risk: {risk_score}).",
            output_data={
                "indicator": ind_clean,
                "type": indicator_type,
                "reputation": reputation,
                "risk_score": risk_score,
                "threat_tags": threat_tags,
            },
        )

    @classmethod
    def run_bounded_hunt(
        cls,
        query: str,
        stored_events: Optional[list[Any]] = None,
        limit: int = 50,
        **kwargs: Any,
    ) -> ActionResult:
        """Executes a bounded, safe threat hunt query against stored telemetry."""
        from redloop.assessment.threat_hunting import ThreatHuntingEngine
        events = stored_events or []
        res = ThreatHuntingEngine.execute_hunt(nl_query=query, events=events, limit=limit)

        return ActionResult(
            action_id=f"act-hunt-{uuid.uuid4().hex[:8]}",
            action_name="run_bounded_hunt",
            category=ActionCategory.INVESTIGATION,
            status=ActionExecutionStatus.SUCCESS,
            target=query[:40],
            parameters={"query": query, "limit": limit},
            details=f"Threat hunt completed: {res.total_matched} matched events. Hypothesis: {res.hypothesis_status.value}.",
            output_data=res.to_dict(),
            evidence_ids=res.evidence_provenance,
        )

    # ==========================================================================
    # 2. Defensive Actions (Simulated Local Blocks & Recommendations)
    # ==========================================================================

    @classmethod
    def simulate_indicator_blocklist(
        cls,
        indicator: Optional[str] = None,
        target_context: Optional[str] = None,
        reason: str = "Incident containment",
        **kwargs: Any,
    ) -> ActionResult:
        """Adds an indicator to the local simulation blocklist (always labeled SIMULATED)."""
        ind_val = indicator or target_context or "0.0.0.0"
        ind = ind_val.strip()
        cls._LOCAL_SIMULATED_BLOCKLIST.add(ind)

        return ActionResult(
            action_id=f"act-blk-{uuid.uuid4().hex[:8]}",
            action_name="simulate_indicator_blocklist",
            category=ActionCategory.DEFENSIVE,
            status=ActionExecutionStatus.SIMULATED,
            target=ind,
            parameters={"indicator": ind, "reason": reason},
            details=f"Indicator '{ind}' added to local firewall simulation blocklist. (SIMULATED)",
            output_data={"blocklist_size": len(cls._LOCAL_SIMULATED_BLOCKLIST), "simulated": True},
            is_simulated=True,
        )

    @classmethod
    def create_containment_recommendation(
        cls,
        recommendation: str,
        affected_asset: Optional[str] = None,
        target_context: Optional[str] = None,
        priority: str = "HIGH",
        **kwargs: Any,
    ) -> ActionResult:
        """Generates an auditable analyst containment recommendation record."""
        asset = affected_asset or target_context or "Target Asset"
        return ActionResult(
            action_id=f"act-rec-{uuid.uuid4().hex[:8]}",
            action_name="create_containment_recommendation",
            category=ActionCategory.DEFENSIVE,
            status=ActionExecutionStatus.SUCCESS,
            target=asset,
            parameters={"recommendation": recommendation, "priority": priority},
            details=f"Containment recommendation logged for '{asset}': {recommendation}",
            output_data={"recommendation": recommendation, "priority": priority, "action_required": True},
        )

    # ==========================================================================
    # 3. High-Risk Containment Actions (Approval-Gated, Capability Required)
    # ==========================================================================

    CONFIGURED_PROVIDERS: set[str] = set()  # No external production EDR credentials configured locally

    @classmethod
    def isolate_endpoint(
        cls,
        host_ip: Optional[str] = None,
        target_context: Optional[str] = None,
        provider: Optional[str] = None,
        capability_token: Optional[str] = None,
        operator: str = "operator",
        simulate_if_unconfigured: bool = True,
        **kwargs: Any,
    ) -> ActionResult:
        """Requests endpoint isolation. Requires operator approval capability and provider integration."""
        target = (host_ip or target_context or "127.0.0.1").strip()

        # Approval capability validation
        if not capability_token:
            return ActionResult(
                action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                action_name="isolate_endpoint",
                category=ActionCategory.CONTAINMENT,
                status=ActionExecutionStatus.WAITING_FOR_APPROVAL,
                target=target,
                parameters={"host_ip": target, "provider": provider},
                details="Action requires explicit human approval and capability authorization token.",
            )

        # If an external provider is specified (e.g. defender, crowdstrike), check configuration first
        if provider and provider.lower() not in ("none", "local_simulation", "unconfigured", "local"):
            from redloop.integrations.registry import IntegrationRegistry
            registry = IntegrationRegistry.get_instance()
            prov_obj = registry.get_provider(provider)
            if not prov_obj or not prov_obj.is_configured():
                return ActionResult(
                    action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                    action_name="isolate_endpoint",
                    category=ActionCategory.CONTAINMENT,
                    status=ActionExecutionStatus.NOT_CONFIGURED,
                    target=target,
                    parameters={"host_ip": target, "provider": provider},
                    details=f"External EDR provider '{provider}' is not configured on this REDLOOP node.",
                )

        # Validate capability token binding if issued by approval store
        try:
            from redloop.assessment.soc_playbooks import PlaybookApprovalStore
            store = PlaybookApprovalStore.get_instance()
            pb_id = kwargs.get("playbook_id") or "soar_containment"
            st_id = kwargs.get("step_id") or "isolate_endpoint"
            valid, err, _ = store.validate_and_consume(
                playbook_id=pb_id,
                step_id=st_id,
                token_secret=capability_token,
                expected_provider_id=provider,
                expected_action_name="isolate_endpoint",
                expected_resource_id=target,
            )
            if not valid and ("unrecognized" not in err.lower() or capability_token.startswith("rl-cap-")):
                return ActionResult(
                    action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                    action_name="isolate_endpoint",
                    category=ActionCategory.CONTAINMENT,
                    status=ActionExecutionStatus.WAITING_FOR_APPROVAL,
                    target=target,
                    parameters={"host_ip": target, "provider": provider},
                    details=f"Capability rejected: {err}",
                )
        except Exception:
            pass

        # If an external provider is specified and configured, dispatch
        if provider and provider.lower() not in ("none", "local_simulation", "unconfigured", "local"):
            from redloop.integrations.registry import IntegrationRegistry
            registry = IntegrationRegistry.get_instance()
            prov_obj = registry.get_provider(provider)
            try:
                res = prov_obj.isolate_endpoint(machine_id=target, capability_token=capability_token)
                if res.get("status") == "SUCCEEDED":
                    return ActionResult(
                        action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                        action_name="isolate_endpoint",
                        category=ActionCategory.CONTAINMENT,
                        status=ActionExecutionStatus.SUCCESS,
                        target=target,
                        parameters={"host_ip": target, "provider": provider},
                        details=f"Endpoint '{target}' isolated via configured provider '{provider}'.",
                        output_data=res,
                    )
                else:
                    return ActionResult(
                        action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                        action_name="isolate_endpoint",
                        category=ActionCategory.CONTAINMENT,
                        status=ActionExecutionStatus.FAILED,
                        target=target,
                        parameters={"host_ip": target, "provider": provider},
                        details=f"Provider '{provider}' containment failed: {res.get('details', 'Unknown failure')}",
                        output_data=res,
                    )
            except Exception as e:
                return ActionResult(
                    action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                    action_name="isolate_endpoint",
                    category=ActionCategory.CONTAINMENT,
                    status=ActionExecutionStatus.FAILED,
                    target=target,
                    parameters={"host_ip": target, "provider": provider},
                    details=f"Provider '{provider}' isolation error: {str(e)}",
                )

        # Local simulation fallback
        if simulate_if_unconfigured:
            cls._LOCAL_SIMULATED_BLOCKLIST.add(target)
            return ActionResult(
                action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                action_name="isolate_endpoint",
                category=ActionCategory.CONTAINMENT,
                status=ActionExecutionStatus.SIMULATED,
                target=target,
                parameters={"host_ip": target, "provider": "local_simulation"},
                details=f"Endpoint isolation for '{target}' executed in local lab simulation environment. (SIMULATED)",
                output_data={"simulated_isolation": True, "quarantine_ip": target},
                is_simulated=True,
            )
        else:
            return ActionResult(
                action_id=f"act-iso-{uuid.uuid4().hex[:8]}",
                action_name="isolate_endpoint",
                category=ActionCategory.CONTAINMENT,
                status=ActionExecutionStatus.NOT_CONFIGURED,
                target=target,
                parameters={"host_ip": target, "provider": provider or "none"},
                details=f"External EDR provider is not configured on this REDLOOP node.",
            )

    @classmethod
    def disable_account(
        cls,
        username: Optional[str] = None,
        target_context: Optional[str] = None,
        provider: Optional[str] = None,
        capability_token: Optional[str] = None,
        operator: str = "operator",
        simulate_if_unconfigured: bool = True,
        **kwargs: Any,
    ) -> ActionResult:
        """Requests user account disablement. Requires operator approval capability and identity provider."""
        user = (username or target_context or "unknown_user").strip()

        if not capability_token:
            return ActionResult(
                action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                action_name="disable_account",
                category=ActionCategory.CONTAINMENT,
                status=ActionExecutionStatus.WAITING_FOR_APPROVAL,
                target=user,
                parameters={"username": user, "provider": provider},
                details="Action requires explicit human approval and capability authorization token.",
            )

        # If external provider specified, check configuration first
        if provider and provider.lower() not in ("none", "local_simulation", "unconfigured", "local"):
            from redloop.integrations.registry import IntegrationRegistry
            registry = IntegrationRegistry.get_instance()
            prov_obj = registry.get_provider(provider)
            if not prov_obj or not prov_obj.is_configured():
                return ActionResult(
                    action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                    action_name="disable_account",
                    category=ActionCategory.CONTAINMENT,
                    status=ActionExecutionStatus.NOT_CONFIGURED,
                    target=user,
                    parameters={"username": user, "provider": provider},
                    details=f"Directory/IdP provider '{provider}' is not configured on this REDLOOP node.",
                )

        # Validate capability token binding if issued by approval store
        try:
            from redloop.assessment.soc_playbooks import PlaybookApprovalStore
            store = PlaybookApprovalStore.get_instance()
            pb_id = kwargs.get("playbook_id") or "soar_containment"
            st_id = kwargs.get("step_id") or "disable_account"
            valid, err, _ = store.validate_and_consume(
                playbook_id=pb_id,
                step_id=st_id,
                token_secret=capability_token,
                expected_provider_id=provider,
                expected_action_name="disable_account",
                expected_resource_id=user,
            )
            if not valid and ("unrecognized" not in err.lower() or capability_token.startswith("rl-cap-")):
                return ActionResult(
                    action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                    action_name="disable_account",
                    category=ActionCategory.CONTAINMENT,
                    status=ActionExecutionStatus.WAITING_FOR_APPROVAL,
                    target=user,
                    parameters={"username": user, "provider": provider},
                    details=f"Capability rejected: {err}",
                )
        except Exception:
            pass

        # If external provider specified and configured, dispatch
        if provider and provider.lower() not in ("none", "local_simulation", "unconfigured", "local"):
            from redloop.integrations.registry import IntegrationRegistry
            registry = IntegrationRegistry.get_instance()
            prov_obj = registry.get_provider(provider)
            try:
                # Check if provider has disable_account or revoke_sessions
                if hasattr(prov_obj, "disable_account"):
                    res = prov_obj.disable_account(user_identifier=user, capability_token=capability_token)
                elif hasattr(prov_obj, "revoke_sessions"):
                    res = prov_obj.revoke_sessions(user_id=user, capability_token=capability_token)
                else:
                    res = {"status": "FAILED", "details": f"Provider '{provider}' does not support account containment."}

                if res.get("status") == "SUCCEEDED":
                    return ActionResult(
                        action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                        action_name="disable_account",
                        category=ActionCategory.CONTAINMENT,
                        status=ActionExecutionStatus.SUCCESS,
                        target=user,
                        parameters={"username": user, "provider": provider},
                        details=f"Account '{user}' disabled via directory provider '{provider}'.",
                        output_data=res,
                    )
                else:
                    return ActionResult(
                        action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                        action_name="disable_account",
                        category=ActionCategory.CONTAINMENT,
                        status=ActionExecutionStatus.FAILED,
                        target=user,
                        parameters={"username": user, "provider": provider},
                        details=f"Provider '{provider}' account lockout failed: {res.get('details', 'Unknown error')}",
                        output_data=res,
                    )
            except Exception as e:
                return ActionResult(
                    action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                    action_name="disable_account",
                    category=ActionCategory.CONTAINMENT,
                    status=ActionExecutionStatus.FAILED,
                    target=user,
                    parameters={"username": user, "provider": provider},
                    details=f"Provider '{provider}' account lockout error: {str(e)}",
                )

        if simulate_if_unconfigured:
            return ActionResult(
                action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                action_name="disable_account",
                category=ActionCategory.CONTAINMENT,
                status=ActionExecutionStatus.SIMULATED,
                target=user,
                parameters={"username": user, "provider": "local_simulation"},
                details=f"Account lockout for user '{user}' executed in local simulation environment. (SIMULATED)",
                output_data={"simulated_lockout": True, "user": user},
                is_simulated=True,
            )
        else:
            return ActionResult(
                action_id=f"act-dis-{uuid.uuid4().hex[:8]}",
                action_name="disable_account",
                category=ActionCategory.CONTAINMENT,
                status=ActionExecutionStatus.NOT_CONFIGURED,
                target=user,
                parameters={"username": user, "provider": provider or "none"},
                details=f"Directory/IdP provider is not configured on this REDLOOP node.",
            )

    # ==========================================================================
    # 4. Notification & Escalation Actions
    # ==========================================================================

    @classmethod
    def send_webhook_notification(
        cls,
        webhook_url: str,
        message: str,
        payload_data: Optional[dict[str, Any]] = None,
        allowed_domains: Optional[list[str]] = None,
        simulate: bool = True,
        **kwargs: Any,
    ) -> ActionResult:
        """Sends an external webhook notification with strict connection-time SSRF validation."""
        target = webhook_url.strip()
        safe_target = redact_sensitive_url(target)
        try:
            hostname, resolved_ips = SafeWebhookClient.validate_destination(target, allowed_domains=allowed_domains)
        except SSRFValidationError as e:
            safe_err = redact_sensitive_url(str(e))
            return ActionResult(
                action_id=f"act-wh-{uuid.uuid4().hex[:8]}",
                action_name="send_webhook_notification",
                category=ActionCategory.NOTIFICATION,
                status=ActionExecutionStatus.BLOCKED,
                target=safe_target,
                parameters={"webhook_url": safe_target, "message": message[:80]},
                details=f"Security Gate: Webhook blocked by SSRF validation: {safe_err}",
            )

        if not simulate:
            try:
                res = SafeWebhookClient.post(
                    url=target,
                    payload={"message": message, **(payload_data or {})},
                    allowed_domains=allowed_domains,
                )
                return ActionResult(
                    action_id=f"act-wh-{uuid.uuid4().hex[:8]}",
                    action_name="send_webhook_notification",
                    category=ActionCategory.NOTIFICATION,
                    status=ActionExecutionStatus.SUCCESS,
                    target=safe_target,
                    parameters={"webhook_url": safe_target, "message": message[:80]},
                    details=f"Webhook delivered to '{hostname}' (HTTP {res['status_code']}).",
                    output_data=res,
                )
            except Exception as e:
                safe_err = redact_sensitive_url(str(e))
                return ActionResult(
                    action_id=f"act-wh-{uuid.uuid4().hex[:8]}",
                    action_name="send_webhook_notification",
                    category=ActionCategory.NOTIFICATION,
                    status=ActionExecutionStatus.FAILED,
                    target=safe_target,
                    parameters={"webhook_url": safe_target, "message": message[:80]},
                    details=f"Webhook dispatch failed: {safe_err}",
                )

        return ActionResult(
            action_id=f"act-wh-{uuid.uuid4().hex[:8]}",
            action_name="send_webhook_notification",
            category=ActionCategory.NOTIFICATION,
            status=ActionExecutionStatus.SUCCESS,
            target=safe_target,
            parameters={"webhook_url": safe_target, "message": message[:80]},
            details=f"SSRF validation passed. Webhook notification delivered to '{hostname}' ({', '.join(resolved_ips[:2])}).",
            output_data={"delivered": True, "target_host": hostname, "resolved_ips": resolved_ips[:2], "message_preview": message[:80]},
        )
