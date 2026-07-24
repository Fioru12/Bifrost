import pytest
import os
from core.scanner import PortScanner, SERVICE_DB
from core.analyzer import TrafficAnalyzer
from core.reporter import EncryptedReporter

def test_port_scanner_init():
    scanner = PortScanner(timeout=0.5, max_threads=50)
    assert scanner.timeout == 0.5
    assert scanner.max_threads == 50

def test_port_scanner_common_ports():
    assert 80 in SERVICE_DB
    assert 443 in SERVICE_DB
    assert 22 in SERVICE_DB
    assert SERVICE_DB[80] == "HTTP"
    assert SERVICE_DB[443] == "HTTPS"

def test_port_scanner_localhost():
    scanner = PortScanner(timeout=1.0, max_threads=50)
    result = scanner.scan("127.0.0.1", [80, 443, 22])
    assert "host" in result
    assert "open_ports" in result
    assert "ports_scanned" in result
    assert result["ports_scanned"] == 3

def test_traffic_analyzer_snapshot():
    analyzer = TrafficAnalyzer()
    snapshot = analyzer.capture_snapshot()
    assert "timestamp" in snapshot
    assert "total_connections" in snapshot
    assert "connections" in snapshot
    assert isinstance(snapshot["connections"], list)

def test_traffic_anomaly_detection():
    analyzer = TrafficAnalyzer()
    mock_snapshot = {
        "timestamp": "2026-07-23 12:00:00",
        "total_connections": 20,
        "connections": [],
        "listening_ports": {4444: 1},
        "remote_ips": {"10.0.0.99": 20},
        "status_breakdown": {"ESTABLISHED": 15, "TIME_WAIT": 60}
    }
    anomalies = analyzer.detect_anomalies(mock_snapshot)
    assert len(anomalies) >= 2
    types = [a["type"] for a in anomalies]
    assert "PORT_SCAN_PATTERN" in types
    assert "SUSPICIOUS_PORT" in types
    assert "EXCESSIVE_TIMEWAIT" in types

def test_reporter_markdown():
    reporter = EncryptedReporter(output_dir="test_reports")
    mock_scan = {
        "host": "127.0.0.1",
        "ports_scanned": 100,
        "open_count": 2,
        "scan_duration_sec": 0.5,
        "open_ports": [
            {"port": 80, "state": "open", "service": "HTTP", "latency_ms": 1.2, "banner": "nginx"},
            {"port": 443, "state": "open", "service": "HTTPS", "latency_ms": 0.8, "banner": None}
        ]
    }
    mock_analysis = {
        "snapshot": {"total_connections": 50, "remote_ips": {"10.0.0.1": 5}},
        "anomalies": [{"type": "HIGH_CONNECTION_VOLUME", "severity": "LOW", "indicator": "10.0.0.1", "details": "test"}],
        "anomaly_count": 1
    }
    path = reporter.generate_report(scan_result=mock_scan, analysis_result=mock_analysis)
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Bifrost Network Security Report" in content
        assert "127.0.0.1" in content
        assert "HTTP" in content

    if os.path.exists(path):
        os.remove(path)

from cryptography.fernet import InvalidToken

def test_reporter_encryption():
    reporter = EncryptedReporter(output_dir="test_reports")
    content = "Top secret network report"
    password = "my_secure_password"

    encrypted = reporter.encrypt_content(content, password)
    decrypted = reporter.decrypt_content(encrypted, password)
    assert decrypted == content

    with pytest.raises(InvalidToken):
        reporter.decrypt_content(encrypted, "wrong_password")

def test_reporter_encrypted_file():
    reporter = EncryptedReporter(output_dir="test_reports")
    path = reporter.generate_report(
        scan_result={"host": "test", "ports_scanned": 10, "open_count": 1, "scan_duration_sec": 0.1,
                      "open_ports": [{"port": 80, "state": "open", "service": "HTTP", "latency_ms": 1.0, "banner": None}]},
        encrypt_password="test123"
    )
    assert os.path.exists(path)
    enc_path = path.replace(".md", ".enc")
    assert os.path.exists(enc_path)

    # Cleanup
    if os.path.exists(path):
        os.remove(path)
    if os.path.exists(enc_path):
        os.remove(enc_path)


from core.discovery import LANDiscovery

def test_guess_device_type_windows():
    d = LANDiscovery()
    assert d._guess_device_type([445, 135]) == "Windows Server / Workstation"

def test_guess_device_type_linux():
    d = LANDiscovery()
    assert d._guess_device_type([22]) == "Linux / Unix Server"

def test_guess_device_type_rdp():
    d = LANDiscovery()
    assert d._guess_device_type([3389]) == "Windows RDP Host"

def test_guess_device_type_web():
    d = LANDiscovery()
    assert d._guess_device_type([80, 443]) == "Web Server / Gateway"

def test_guess_device_type_iot():
    d = LANDiscovery()
    assert d._guess_device_type([53]) == "Network Device / IoT"

def test_sweep_invalid_subnet():
    d = LANDiscovery()
    result = d.sweep_subnet("not_a_subnet")
    assert "error" in result
    assert result["hosts"] == []

def test_sweep_small_subnet():
    d = LANDiscovery(timeout=0.3)
    result = d.sweep_subnet("127.0.0.0/30", max_workers=5)
    assert "subnet" in result
    assert "total_scanned" in result
    assert "live_hosts_count" in result
    assert "scan_duration_sec" in result
    assert isinstance(result["hosts"], list)

def test_check_host_localhost():
    d = LANDiscovery(timeout=0.5)
    res = d._check_host("127.0.0.1")
    assert res is None or isinstance(res, dict)

def test_os_from_ttl_linux():
    d = LANDiscovery()
    assert "Linux" in d._get_os_from_ttl(64)

def test_os_from_ttl_windows():
    d = LANDiscovery()
    assert "Windows" in d._get_os_from_ttl(128)

def test_os_from_ttl_network_device():
    d = LANDiscovery()
    assert "Router" in d._get_os_from_ttl(1)

def test_ttl_os_map_coverage():
    d = LANDiscovery()
    for ttl_val in [1, 3, 16, 32, 64, 128, 200]:
        result = d._get_os_from_ttl(ttl_val)
        assert isinstance(result, str)
        assert len(result) > 0
