import sys
import argparse
import json
from core.scanner import PortScanner
from core.analyzer import TrafficAnalyzer
from core.reporter import EncryptedReporter

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_scan(host: str, ports=None, common=True):
    scanner = PortScanner()
    print("=" * 65)
    print(" Bifrost - Network Port Scanner")
    print("=" * 65)
    print(f"[*] Target: {host}")

    if common:
        result = scanner.scan_common(host)
    elif ports:
        result = scanner.scan(host, ports)
    else:
        result = scanner.scan_common(host)

    print(f"[*] Ports scanned: {result['ports_scanned']}")
    print(f"[*] Open ports: {result['open_count']}")
    print(f"[*] Scan duration: {result['scan_duration_sec']}s")

    if result["open_ports"]:
        print("\n Open Ports:")
        print(f" {'PORT':<8} {'SERVICE':<15} {'LATENCY':<10} {'BANNER'}")
        print(f" {'-'*6:<8} {'-'*12:<15} {'-'*8:<10} {'-'*30}")
        for p in result["open_ports"]:
            banner = (p.get("banner") or "-")[:40]
            print(f" {p['port']:<8} {p['service']:<15} {p['latency_ms']:<10}ms {banner}")
    else:
        print("\n No open ports detected.")

    print("=" * 65)
    return result

def run_analyze():
    ta = TrafficAnalyzer()
    print("=" * 65)
    print(" Bifrost - Live Traffic Analyzer")
    print("=" * 65)

    result = ta.run_analysis()
    snap = result["snapshot"]

    print(f"[*] Snapshot time: {snap['timestamp']}")
    print(f"[*] Total connections: {snap['total_connections']}")
    print(f"[*] Unique remote IPs: {len(snap.get('remote_ips', {}))}")
    print(f"[*] Anomalies detected: {result['anomaly_count']}")

    if result["anomalies"]:
        print("\n Anomalies Found:")
        for a in result["anomalies"]:
            print(f"  [{a['severity']}] {a['type']}: {a['details']}")
    else:
        print("\n No anomalies detected.")

    print("=" * 65)
    return result

def run_full(host: str = "127.0.0.1", encrypt_password=None):
    print("=" * 65)
    print(" Bifrost - Full Network Security Analysis")
    print("=" * 65)

    scan = run_scan(host)
    analysis = run_analyze()

    reporter = EncryptedReporter()
    print("\n[*] Generating encrypted network security report...")
    path = reporter.generate_report(
        scan_result=scan,
        analysis_result=analysis,
        encrypt_password=encrypt_password
    )
    print(f"[SUCCESS] Report saved at: {path}")
    print("=" * 65)
    return scan, analysis

def main():
    parser = argparse.ArgumentParser(description="Bifrost: Network Telemetry & Port Analysis")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    scan_parser = subparsers.add_parser("scan", help="Scan target host for open ports")
    scan_parser.add_argument("host", help="Target host IP or hostname")
    scan_parser.add_argument("--ports", nargs="+", type=int, help="Specific ports to scan")

    subparsers.add_parser("analyze", help="Analyze live network traffic")

    full_parser = subparsers.add_parser("full", help="Run full scan + analysis + report")
    full_parser.add_argument("--host", default="127.0.0.1")
    full_parser.add_argument("--password", help="Encrypt report with this password")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.host, ports=args.ports)
    elif args.command == "analyze":
        run_analyze()
    elif args.command == "full":
        run_full(args.host, encrypt_password=args.password)
    else:
        run_full("127.0.0.1")

if __name__ == "__main__":
    main()
