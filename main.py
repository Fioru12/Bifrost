import sys
import argparse
from core.scanner import PortScanner
from core.analyzer import TrafficAnalyzer
from core.reporter import EncryptedReporter
from core.intel import IPIntelligence
from core.discovery import LANDiscovery
from core.colors import Colors

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_discover(subnet: str = "192.168.1.0/24"):
    discovery = LANDiscovery()
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Bifrost - LAN Asset Discovery & Network Inventory{Colors.ENDC}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Sweeping Subnet: {subnet}")

    res = discovery.sweep_subnet(subnet)
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Total IPs scanned: {res['total_scanned']}")
    print(f"{Colors.GREEN}[*]{Colors.ENDC} Live hosts found: {Colors.BOLD}{res['live_hosts_count']}{Colors.ENDC}")
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Scan duration: {res['scan_duration_sec']}s")

    if res["hosts"]:
        print(f"\n {Colors.GREEN}Discovered Assets:{Colors.ENDC}")
        print(f" {'IP ADDRESS':<16} {'HOSTNAME':<22} {'OS GUESS':<24} {'DEVICE TYPE':<26} {'OPEN PORTS'}")
        print(f" {'-'*14:<16} {'-'*20:<22} {'-'*22:<24} {'-'*24:<26} {'-'*15}")
        for h in res["hosts"]:
            ports_str = ",".join(map(str, h["open_ports"])) if h["open_ports"] else "None"
            os_guess = h.get("os_guess", "Unknown")
            print(f" {h['ip']:<16} {Colors.BOLD}{h['hostname']:<22}{Colors.ENDC} {os_guess:<24} {h['device_type']:<26} {ports_str}")
        print()
        for h in res["hosts"]:
            ports_str = ",".join(map(str, h["open_ports"])) if h["open_ports"] else "None"
            os_guess = h.get("os_guess", "Unknown")
            print(f"{h['ip']} | {h['hostname']} | {os_guess} | {h['device_type']} | {ports_str} | UP")
    else:
        print(f"\n {Colors.WARNING}No active hosts discovered on subnet {subnet}.{Colors.ENDC}")

    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    return res

def run_scan(host: str, ports=None, common=True, enrich=False):
    scanner = PortScanner()
    intel = IPIntelligence()
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Bifrost - Network Port Scanner{Colors.ENDC}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Target: {host}")

    if common:
        result = scanner.scan_common(host)
    elif ports:
        result = scanner.scan(host, ports)
    else:
        result = scanner.scan_common(host)

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Ports scanned: {result['ports_scanned']}")
    print(f"{Colors.GREEN}[*]{Colors.ENDC} Open ports: {Colors.BOLD}{result['open_count']}{Colors.ENDC}")
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Scan duration: {result['scan_duration_sec']}s")

    if result["open_ports"]:
        print(f"\n {Colors.GREEN}Open Ports:{Colors.ENDC}")
        print(f" {'PORT':<8} {'SERVICE':<15} {'LATENCY':<10} {'BANNER'}")
        print(f" {'-'*6:<8} {'-'*12:<15} {'-'*8:<10} {'-'*30}")
        for p in result["open_ports"]:
            banner = (p.get("banner") or "-")[:40]
            print(f" {p['port']:<8} {Colors.BOLD}{p['service']:<15}{Colors.ENDC} {p['latency_ms']:<10}ms {banner}")
    else:
        print(f"\n {Colors.WARNING}No open ports detected.{Colors.ENDC}")

    if enrich:
        print(f"\n{Colors.CYAN}[*]{Colors.ENDC} Enriching target with IP intelligence...")
        geo = intel.geolocate(host)
        whois = intel.whois_lookup(host)
        if geo:
            tags = intel.get_threat_tags(geo)
            print(f" {Colors.CYAN}Location:{Colors.ENDC} {geo['city']}, {geo['region']}, {geo['country']}")
            print(f" {Colors.CYAN}ISP:{Colors.ENDC} {geo['isp']}")
            print(f" {Colors.CYAN}Org:{Colors.ENDC} {geo['org']}")
            print(f" {Colors.CYAN}AS:{Colors.ENDC} {geo['as']}")
            if tags:
                print(f" {Colors.WARNING}Threat Tags:{Colors.ENDC} {', '.join(tags)}")
            else:
                print(f" {Colors.GREEN}Threat Tags:{Colors.ENDC} None detected")
        if whois:
            print(f" {Colors.CYAN}Whois:{Colors.ENDC} {whois.get('name', host)} ({whois.get('country', 'N/A')})")
        result["geo"] = geo
        result["whois"] = whois

    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    return result

def run_analyze():
    ta = TrafficAnalyzer()
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Bifrost - Live Traffic Analyzer{Colors.ENDC}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)

    result = ta.run_analysis()
    snap = result["snapshot"]

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Snapshot time: {snap['timestamp']}")
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Total connections: {snap['total_connections']}")
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Unique remote IPs: {len(snap.get('remote_ips', {}))}")
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Anomalies detected: {Colors.BOLD}{result['anomaly_count']}{Colors.ENDC}")

    if result["anomalies"]:
        print(f"\n {Colors.FAIL}Anomalies Found:{Colors.ENDC}")
        for a in result["anomalies"]:
            sev_color = Colors.FAIL if a['severity'] == 'HIGH' else Colors.WARNING
            print(f"  {sev_color}[{a['severity']}]{Colors.ENDC} {a['type']}: {a['details']}")
    else:
        print(f"\n {Colors.GREEN}No anomalies detected.{Colors.ENDC}")

    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    return result

def run_full(host: str = "127.0.0.1", encrypt_password=None, enrich=False):
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Bifrost - Full Network Security Analysis{Colors.ENDC}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)

    scan = run_scan(host, enrich=enrich)
    analysis = run_analyze()

    reporter = EncryptedReporter()
    print(f"\n{Colors.CYAN}[*]{Colors.ENDC} Generating encrypted network security report...")
    path = reporter.generate_report(
        scan_result=scan,
        analysis_result=analysis,
        encrypt_password=encrypt_password
    )
    print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Report saved at: {path}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    return scan, analysis

def main():
    parser = argparse.ArgumentParser(description="Bifrost: Network Telemetry & Port Analysis")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    scan_parser = subparsers.add_parser("scan", help="Scan target host for open ports")
    scan_parser.add_argument("host", help="Target host IP or hostname")
    scan_parser.add_argument("--ports", nargs="+", type=int, help="Specific ports to scan")
    scan_parser.add_argument("--enrich", action="store_true", help="Enrich results with IP geolocation and Whois data")

    disc_parser = subparsers.add_parser("discover", help="Perform LAN asset discovery sweep")
    disc_parser.add_argument("subnet", default="192.168.1.0/24", nargs="?", help="Subnet CIDR (e.g. 192.168.1.0/24)")

    subparsers.add_parser("analyze", help="Analyze live network traffic")

    full_parser = subparsers.add_parser("full", help="Run full scan + analysis + report")
    full_parser.add_argument("--host", default="127.0.0.1")
    full_parser.add_argument("--password", help="Encrypt report with this password")
    full_parser.add_argument("--enrich", action="store_true", help="Enrich results with IP geolocation and Whois data")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args.host, ports=args.ports, enrich=args.enrich)
    elif args.command == "discover":
        run_discover(args.subnet)
    elif args.command == "analyze":
        run_analyze()
    elif args.command == "full":
        run_full(args.host, encrypt_password=args.password, enrich=args.enrich)
    else:
        run_full("127.0.0.1")

if __name__ == "__main__":
    main()
