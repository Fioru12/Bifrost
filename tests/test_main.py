"""Tests for main.py's CLI wiring - previously 0% covered by any test."""
import main


def test_run_scan_with_explicit_ports_only_scans_those_ports(monkeypatch):
    """
    Regression test: main()'s "scan" subcommand called
    run_scan(args.host, ports=args.ports, enrich=args.enrich) without ever
    setting common=False, so run_scan's `if common: ... elif ports: ...`
    branch always took the `common=True` path regardless of --ports -
    the --ports CLI flag was silently ignored, always falling back to
    scan_common()'s fixed port list. Found by actually running
    `python main.py scan 127.0.0.1 --ports 22 80 443` and seeing
    "Ports scanned: 25" instead of 3.
    """
    calls = {}

    class FakeScanner:
        def scan(self, host, ports):
            calls["method"] = "scan"
            calls["ports"] = ports
            return {"ports_scanned": len(ports), "open_count": 0, "scan_duration_sec": 0, "open_ports": []}

        def scan_common(self, host):
            calls["method"] = "scan_common"
            return {"ports_scanned": 25, "open_count": 0, "scan_duration_sec": 0, "open_ports": []}

    monkeypatch.setattr(main, "PortScanner", lambda: FakeScanner())
    monkeypatch.setattr(main, "IPIntelligence", lambda: None)

    monkeypatch.setattr("sys.argv", ["main.py", "scan", "127.0.0.1", "--ports", "22", "80", "443"])
    main.main()

    assert calls["method"] == "scan"
    assert calls["ports"] == [22, 80, 443]


def test_run_scan_without_ports_uses_common_scan(monkeypatch):
    """The default (no --ports) path must still use scan_common()."""
    calls = {}

    class FakeScanner:
        def scan(self, host, ports):
            calls["method"] = "scan"
            return {"ports_scanned": len(ports), "open_count": 0, "scan_duration_sec": 0, "open_ports": []}

        def scan_common(self, host):
            calls["method"] = "scan_common"
            return {"ports_scanned": 25, "open_count": 0, "scan_duration_sec": 0, "open_ports": []}

    monkeypatch.setattr(main, "PortScanner", lambda: FakeScanner())
    monkeypatch.setattr(main, "IPIntelligence", lambda: None)

    monkeypatch.setattr("sys.argv", ["main.py", "scan", "127.0.0.1"])
    main.main()

    assert calls["method"] == "scan_common"
