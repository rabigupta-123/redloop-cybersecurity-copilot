"""Unit tests for hardened transport security (anti-SSRF, DNS rebinding, redirect defense)."""

from __future__ import annotations

import socket
import pytest
import httpx

from redloop.transport import (
    BlockedDestinationError,
    DNSRebindingError,
    HardenedHTTPTransport,
    SecurityTransportError,
    get_hardened_async_client,
    get_hardened_client,
    secure_get,
    secure_post,
    validate_and_pin_host,
)


def test_cloud_metadata_ip_blocked() -> None:
    """Attempting to fetch AWS/GCP/Azure link-local metadata IP 169.254.169.254 must be blocked."""
    client = get_hardened_client()
    with pytest.raises(BlockedDestinationError) as exc_info:
        client.get("http://169.254.169.254/latest/meta-data")
    assert "blocked" in str(exc_info.value).lower()


def test_cloud_metadata_hostname_blocked() -> None:
    """Attempting to fetch metadata.google.internal must be blocked."""
    client = get_hardened_client()
    with pytest.raises(BlockedDestinationError) as exc_info:
        client.get("http://metadata.google.internal/computeMetadata/v1/")
    assert "forbidden" in str(exc_info.value).lower() or "blocked" in str(exc_info.value).lower()


def test_loopback_ipv4_blocked() -> None:
    """Attempting to connect to 127.0.0.1 must be blocked."""
    client = get_hardened_client()
    with pytest.raises(BlockedDestinationError):
        client.get("http://127.0.0.1:8080/admin")


def test_loopback_ipv6_blocked() -> None:
    """Attempting to connect to IPv6 [::1] must be blocked."""
    client = get_hardened_client()
    with pytest.raises(BlockedDestinationError):
        client.get("http://[::1]:8080/admin")


def test_rfc1918_private_ips_blocked() -> None:
    """RFC-1918 private subnets (10/8, 172.16/12, 192.168/16) must all be blocked."""
    client = get_hardened_client()
    for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
        with pytest.raises(BlockedDestinationError):
            client.get(f"http://{ip}/status")


def test_rfc6598_cgnat_blocked() -> None:
    """RFC-6598 carrier-grade NAT (100.64.0.0/10) must be blocked."""
    client = get_hardened_client()
    with pytest.raises(BlockedDestinationError):
        client.get("http://100.64.0.1/internal")


def test_dns_rebinding_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hostname initially resolving to public IP that subsequently resolves to 127.0.0.1 must trigger DNSRebindingError."""
    pinned_ips: dict[str, str] = {}
    host = "rebind.example.org"
    port = 80

    # 1. First resolution: public IP (e.g. 93.184.216.34)
    public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: public_addrinfo)
    pinned = validate_and_pin_host(host, port, pinned_ips)
    assert pinned == "93.184.216.34"
    assert pinned_ips[host] == "93.184.216.34"

    # 2. Second resolution: attacker changes DNS to 127.0.0.1 (rebinding attack)
    loopback_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: loopback_addrinfo)

    with pytest.raises(DNSRebindingError) as exc_info:
        validate_and_pin_host(host, port, pinned_ips)
    assert "DNS rebinding detected" in str(exc_info.value)
    assert issubclass(DNSRebindingError, BlockedDestinationError)
    assert issubclass(DNSRebindingError, SecurityTransportError)


def test_redirect_to_loopback_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Following a redirect (with follow_redirects=True) that targets 127.0.0.1 must be blocked."""
    client = get_hardened_client(follow_redirects=True)

    # Mock handle_request to return 302 on initial public target
    orig_handle = HardenedHTTPTransport.handle_request

    def mock_handle(self: HardenedHTTPTransport, request: httpx.Request) -> httpx.Response:
        if request.url.host == "public-service.example.com":
            return httpx.Response(
                status_code=302,
                headers={"Location": "http://127.0.0.1:8080/secret"},
                request=request,
            )
        return orig_handle(self, request)

    monkeypatch.setattr(HardenedHTTPTransport, "handle_request", mock_handle)

    # When client requests public-service.example.com, it follows redirect to 127.0.0.1 and gets blocked
    with pytest.raises(BlockedDestinationError):
        client.get("http://public-service.example.com/")


def test_redirects_disabled_by_default() -> None:
    """Redirects must be disabled by default (follow_redirects=False)."""
    client = get_hardened_client()
    assert client.follow_redirects is False


def test_secure_get_post_convenience(monkeypatch: pytest.MonkeyPatch) -> None:
    """secure_get and secure_post reject blocked destinations."""
    with pytest.raises(BlockedDestinationError):
        secure_get("http://169.254.169.254/")

    with pytest.raises(BlockedDestinationError):
        secure_post("http://127.0.0.1:9000/api")


def test_async_client_blocked_destination() -> None:
    """Hardened async client transport blocks loopback and metadata before socket connect."""
    client = get_hardened_async_client()
    req = httpx.Request("GET", "http://127.0.0.1:8080/test")
    coro = client._transport.handle_async_request(req)
    with pytest.raises(BlockedDestinationError) as exc_info:
        try:
            coro.send(None)
        except StopIteration:
            pass
    assert "blocked" in str(exc_info.value).lower()
