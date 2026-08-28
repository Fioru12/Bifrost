"""Tests added following code review for:
1. TTL-based OS fingerprinting being clearly labeled unreliable (core/discovery.py)
2. IPv6 support in core/scanner.py and core/analyzer.py

All tests use mocks -- none require real network access.
"""
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.discovery import LANDiscovery
from core.scanner import PortScanner
from core.analyzer import TrafficAnalyzer


# ---------------------------------------------------------------------------
# 1. TTL / OS fingerprinting must be presented as unreliable, not a real guess
# ---------------------------------------------------------------------------

def test_local_send_ttl_is_documented_as_unreliable():
    """The method that reads IP_TTL from a connected TCP socket must be
    named/documented so it's clear it reports the LOCAL outbound TTL, not
    the remote target's TTL."""
    d = LANDiscovery()
    assert hasattr(d, "_get_local_send_ttl")
    doc = d._get_local_send_ttl.__doc__ or ""
    assert "LOCAL" in doc or "local" in doc
    assert "remote" in doc.lower()


def test_check_host_marks_os_guess_as_unreliable(monkeypatch):
    """_check_host must never present the TTL-derived OS guess as a
    trustworthy remote fingerprint: the dict must carry an explicit
    unreliable marker."""
    d = LANDiscovery(timeout=0.1)

    monkeypatch.setattr(d, "_get_local_send_ttl", lambda ip: 128)

    def fake_socket(*args, **kwargs):
        s = MagicMock()
        s.connect_ex.return_value = 0
        return s

    with patch("socket.socket", side_effect=fake_socket), \
         patch("socket.gethostbyaddr", return_value=("host.local", [], [])):
        result = d._check_host("192.168.1.10")

    assert result is not None
    assert result["os_guess_reliable"] is False
    assert "unreliable" in result["os_guess"].lower()
    assert result["local_ttl"] == 128


def test_check_host_os_guess_unknown_when_ttl_unavailable(monkeypatch):
    d = LANDiscovery(timeout=0.1)
    monkeypatch.setattr(d, "_get_local_send_ttl", lambda ip: None)

    def fake_socket(*args, **kwargs):
        s = MagicMock()
        s.connect_ex.return_value = 0
        return s

    with patch("socket.socket", side_effect=fake_socket), \
         patch("socket.gethostbyaddr", side_effect=socket.herror):
        result = d._check_host("192.168.1.20")

    assert result is not None
    assert result["os_guess"] == "Unknown"
    assert result["os_guess_reliable"] is False


def test_get_local_send_ttl_reads_ip_ttl_socket_option():
    """Sanity-check the underlying mechanism: it reads IPPROTO_IP/IP_TTL off
    a connected socket -- confirming (via mock) that this is indeed the
    local/outbound value the OS applies, not something read from the
    received packet's IP header."""
    d = LANDiscovery(timeout=0.1)
    fake_sock = MagicMock()
    fake_sock.getsockopt.return_value = 64

    with patch("socket.socket", return_value=fake_sock):
        ttl = d._get_local_send_ttl("10.0.0.5")

    assert ttl == 64
    fake_sock.getsockopt.assert_called_once_with(socket.IPPROTO_IP, socket.IP_TTL)
    fake_sock.connect.assert_called_once()


# ---------------------------------------------------------------------------
# 2. IPv6 support: scanner address-family resolution
# ---------------------------------------------------------------------------

def test_scanner_resolve_picks_up_ipv6_family():
    scanner = PortScanner(timeout=0.1)
    fake_getaddrinfo_result = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0)),
    ]
    with patch("socket.getaddrinfo", return_value=fake_getaddrinfo_result) as mock_gai:
        resolved = scanner._resolve("::1", 80)

    mock_gai.assert_called_once()
    assert resolved is not None
    family, sockaddr = resolved
    assert family == socket.AF_INET6
    assert sockaddr == ("::1", 80, 0, 0)


def test_scanner_resolve_picks_up_ipv4_family():
    scanner = PortScanner(timeout=0.1)
    fake_getaddrinfo_result = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]
    with patch("socket.getaddrinfo", return_value=fake_getaddrinfo_result):
        resolved = scanner._resolve("127.0.0.1", 80)

    assert resolved is not None
    family, sockaddr = resolved
    assert family == socket.AF_INET
    assert sockaddr == ("127.0.0.1", 80)


def test_scanner_resolve_returns_none_on_failure():
    scanner = PortScanner(timeout=0.1)
    with patch("socket.getaddrinfo", side_effect=socket.gaierror):
        assert scanner._resolve("not-a-real-host.invalid", 80) is None


def test_scan_port_uses_resolved_ipv6_family(monkeypatch):
    """_scan_port must create the socket with the family returned by
    _resolve (AF_INET6), not hardcode AF_INET."""
    scanner = PortScanner(timeout=0.1)
    monkeypatch.setattr(
        scanner, "_resolve", lambda host, port: (socket.AF_INET6, ("::1", 80, 0, 0))
    )
    monkeypatch.setattr(scanner, "_grab_banner", lambda sock, port=None: None)

    created_families = []

    def fake_socket(family, socktype):
        created_families.append(family)
        s = MagicMock()
        s.connect_ex.return_value = 0
        return s

    with patch("socket.socket", side_effect=fake_socket):
        result = scanner._scan_port("::1", 80)

    assert created_families == [socket.AF_INET6]
    assert result is not None
    assert result["port"] == 80
    assert result["state"] == "open"


# ---------------------------------------------------------------------------
# 2b. IPv6 support: analyzer address parsing
# ---------------------------------------------------------------------------

def test_format_addr_brackets_ipv6():
    assert TrafficAnalyzer._format_addr("::1", 8080) == "[::1]:8080"
    assert TrafficAnalyzer._format_addr("127.0.0.1", 8080) == "127.0.0.1:8080"


def test_split_addr_handles_ipv6_bracket_notation():
    host, port = TrafficAnalyzer._split_addr("[fe80::1]:443")
    assert host == "fe80::1"
    assert port == "443"


def test_split_addr_handles_ipv4():
    host, port = TrafficAnalyzer._split_addr("192.168.1.5:22")
    assert host == "192.168.1.5"
    assert port == "22"


def test_split_addr_handles_na():
    assert TrafficAnalyzer._split_addr("N/A") == (None, None)


def test_capture_snapshot_correctly_parses_ipv6_connections(monkeypatch):
    """Regression test: previously `c["remote"].split(":")[0]` and
    `c["local"].split(":")[-1]` would mis-parse IPv6 addresses (which
    contain multiple colons themselves), corrupting listening_ports and
    remote_ips. With bracket-aware formatting/parsing this must work."""
    fake_conn = SimpleNamespace(
        laddr=SimpleNamespace(ip="::1", port=8443),
        raddr=SimpleNamespace(ip="2001:db8::1", port=443),
        status="ESTABLISHED",
        pid=1234,
    )

    analyzer = TrafficAnalyzer()
    with patch("psutil.net_connections", return_value=[fake_conn]):
        snapshot = analyzer.capture_snapshot()

    assert snapshot["connections"][0]["local"] == "[::1]:8443"
    assert snapshot["connections"][0]["remote"] == "[2001:db8::1]:443"
    assert snapshot["listening_ports"] == {8443: 1}
    assert snapshot["remote_ips"] == {"2001:db8::1": 1}


def test_capture_snapshot_still_parses_ipv4_connections(monkeypatch):
    fake_conn = SimpleNamespace(
        laddr=SimpleNamespace(ip="127.0.0.1", port=5432),
        raddr=SimpleNamespace(ip="10.0.0.9", port=54321),
        status="ESTABLISHED",
        pid=42,
    )

    analyzer = TrafficAnalyzer()
    with patch("psutil.net_connections", return_value=[fake_conn]):
        snapshot = analyzer.capture_snapshot()

    assert snapshot["listening_ports"] == {5432: 1}
    assert snapshot["remote_ips"] == {"10.0.0.9": 1}


# ---------------------------------------------------------------------------
# 3. Active HTTP banner-grab probe (bonus coverage)
# ---------------------------------------------------------------------------

def test_grab_banner_sends_active_probe_for_http_port_when_passive_fails():
    scanner = PortScanner(timeout=0.1)
    sock = MagicMock()
    # First recv (passive) times out, second recv (after probe) returns data.
    sock.recv.side_effect = [socket.timeout(), b"HTTP/1.0 200 OK\r\n"]

    banner = scanner._grab_banner(sock, port=80)

    sock.sendall.assert_called_once_with(b"HEAD / HTTP/1.0\r\n\r\n")
    assert banner == "HTTP/1.0 200 OK"


def test_grab_banner_stays_passive_for_non_http_port():
    scanner = PortScanner(timeout=0.1)
    sock = MagicMock()
    sock.recv.side_effect = socket.timeout()

    banner = scanner._grab_banner(sock, port=22)

    sock.sendall.assert_not_called()
    assert banner is None
