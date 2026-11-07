"""Hardened HTTP transport and clients for RedLoop.

Defenses provided:
- Socket-level pinning of resolved destination IP (anti-DNS-rebinding).
- Strict blocking of loopback, RFC-1918, RFC-6598, link-local, multicast,
  and cloud metadata endpoints (AWS, GCP, Azure) at pre-flight and socket level.
- Redirect protection: disabled by default, strictly re-validated if enabled.
- Fail-closed security architecture.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

import httpcore
import httpcore._backends.sync
import httpcore._exceptions
import httpx


class SecurityTransportError(Exception):
    """Base exception for transport security violations."""


class BlockedDestinationError(SecurityTransportError):
    """Raised when destination IP or host is blocked (RFC 1918, 6598, loopback, cloud metadata, etc.)."""


class DNSRebindingError(BlockedDestinationError):
    """Raised when DNS rebinding is detected."""


BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # RFC 1918 Private Addresses
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # RFC 6598 Carrier-grade NAT
    ipaddress.ip_network("100.64.0.0/10"),
    # Link-local & Cloud Metadata
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    # Multicast, Broadcast, Unspecified
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
]

BLOCKED_HOSTNAMES: set[str] = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "metadata.azure.internal",
    "localhost",
}


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if IP is in any blocked range."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in BLOCKED_NETWORKS)


def validate_and_pin_host(host: str, port: int, pinned_ips: dict[str, str]) -> str:
    """Validate host and resolve destination IP, pinning it against rebinding attacks.

    Raises:
        BlockedDestinationError: If host or resolved IP is forbidden.
        DNSRebindingError: If host previously pinned resolves to a different IP or blocked IP.
    """
    cleaned_host = host.strip("[]").lower()
    if cleaned_host in BLOCKED_HOSTNAMES:
        raise BlockedDestinationError(
            f"Host '{host}' is a forbidden cloud metadata or local hostname"
        )

    # Check if host is a literal IP address
    try:
        ip_obj = ipaddress.ip_address(cleaned_host)
        if is_blocked_ip(ip_obj):
            raise BlockedDestinationError(
                f"Destination IP {host} is blocked by security policy"
            )
        return str(ip_obj)
    except ValueError:
        pass

    # Resolve domain name to IP addresses
    try:
        addr_infos = socket.getaddrinfo(
            host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except SecurityTransportError:
        raise
    except Exception as exc:
        raise SecurityTransportError(f"Failed to resolve host '{host}': {exc}") from exc

    resolved_ips: list[str] = []
    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if is_blocked_ip(ip_obj):
            if host in pinned_ips:
                raise DNSRebindingError(
                    f"DNS rebinding detected for '{host}': previously pinned to "
                    f"{pinned_ips[host]}, now resolved to blocked IP {ip_str}"
                )
            raise BlockedDestinationError(
                f"Host '{host}' resolved to blocked destination {ip_str}"
            )
        resolved_ips.append(ip_str)

    if not resolved_ips:
        raise BlockedDestinationError(
            f"Host '{host}' did not resolve to any permitted destination"
        )

    if host in pinned_ips:
        pinned = pinned_ips[host]
        if pinned not in resolved_ips:
            raise DNSRebindingError(
                f"DNS rebinding detected for '{host}': previously pinned to "
                f"{pinned}, now resolved to {resolved_ips}"
            )
        return pinned

    chosen = resolved_ips[0]
    pinned_ips[host] = chosen
    return chosen


class HardenedSyncBackend(httpcore.SyncBackend):
    """Synchronous network backend that validates and pins destination IPs at the socket level."""

    def __init__(self, pinned_ips: dict[str, str] | None = None) -> None:
        super().__init__()
        self.pinned_ips: dict[str, str] = pinned_ips if pinned_ips is not None else {}

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        pinned_ip = validate_and_pin_host(host, port, self.pinned_ips)
        if socket_options is None:
            socket_options = []
        address = (pinned_ip, port)
        source_address = None if local_address is None else (local_address, 0)
        exc_map = {
            socket.timeout: httpcore.ConnectTimeout,
            OSError: httpcore.ConnectError,
        }
        with httpcore._exceptions.map_exceptions(exc_map):
            sock = socket.create_connection(
                address,
                timeout,
                source_address=source_address,
            )
            for option in socket_options:
                sock.setsockopt(*option)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return httpcore._backends.sync.SyncStream(sock)


class HardenedAsyncBackend(httpcore.AnyIOBackend):
    """Asynchronous network backend that validates and pins destination IPs at the socket level."""

    def __init__(self, pinned_ips: dict[str, str] | None = None) -> None:
        super().__init__()
        self.pinned_ips: dict[str, str] = pinned_ips if pinned_ips is not None else {}

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        pinned_ip = validate_and_pin_host(host, port, self.pinned_ips)
        return await super().connect_tcp(
            pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class HardenedHTTPTransport(httpx.HTTPTransport):
    """Hardened HTTP transport enforcing anti-rebinding and destination restrictions."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.pinned_ips: dict[str, str] = {}
        self._network_backend = HardenedSyncBackend(self.pinned_ips)
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._pool._ssl_context if hasattr(self._pool, "_ssl_context") else None,
            network_backend=self._network_backend,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        validate_and_pin_host(request.url.host, port, self.pinned_ips)
        return super().handle_request(request)


class HardenedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """Hardened Async HTTP transport enforcing anti-rebinding and destination restrictions."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.pinned_ips: dict[str, str] = {}
        self._network_backend = HardenedAsyncBackend(self.pinned_ips)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self._pool._ssl_context if hasattr(self._pool, "_ssl_context") else None,
            network_backend=self._network_backend,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        validate_and_pin_host(request.url.host, port, self.pinned_ips)
        return await super().handle_async_request(request)


def get_hardened_client(
    follow_redirects: bool = False,
    timeout: float | httpx.Timeout = 15.0,
    **kwargs: Any,
) -> httpx.Client:
    """Return an httpx.Client configured with HardenedHTTPTransport.

    Redirects are disallowed by default.
    """
    transport = kwargs.pop("transport", None) or HardenedHTTPTransport()
    return httpx.Client(
        transport=transport,
        follow_redirects=follow_redirects,
        timeout=timeout,
        trust_env=False,
        **kwargs,
    )


def get_hardened_async_client(
    follow_redirects: bool = False,
    timeout: float | httpx.Timeout = 15.0,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Return an httpx.AsyncClient configured with HardenedAsyncHTTPTransport.

    Redirects are disallowed by default.
    """
    transport = kwargs.pop("transport", None) or HardenedAsyncHTTPTransport()
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=follow_redirects,
        timeout=timeout,
        trust_env=False,
        **kwargs,
    )


def secure_get(
    url: str,
    *,
    params: Any = None,
    headers: Mapping[str, str] | None = None,
    cookies: Any = None,
    auth: Any = None,
    follow_redirects: bool = False,
    timeout: float | httpx.Timeout = 15.0,
    **kwargs: Any,
) -> httpx.Response:
    """Execute a hardened synchronous GET request."""
    with get_hardened_client(follow_redirects=follow_redirects, timeout=timeout) as client:
        return client.get(
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            **kwargs,
        )


def secure_post(
    url: str,
    *,
    data: Any = None,
    files: Any = None,
    json: Any = None,
    params: Any = None,
    headers: Mapping[str, str] | None = None,
    cookies: Any = None,
    auth: Any = None,
    follow_redirects: bool = False,
    timeout: float | httpx.Timeout = 15.0,
    **kwargs: Any,
) -> httpx.Response:
    """Execute a hardened synchronous POST request."""
    with get_hardened_client(follow_redirects=follow_redirects, timeout=timeout) as client:
        return client.post(
            url,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            auth=auth,
            **kwargs,
        )
