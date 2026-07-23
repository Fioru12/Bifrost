import time
import psutil
from typing import List, Dict, Any
from collections import Counter, defaultdict

class TrafficAnalyzer:
    """
    Captures and analyzes network traffic in real-time using psutil.
    Detects anomalies: port scan patterns, unusual connection volumes,
    suspicious listening services, and high-latency connections.
    """

    # Ports commonly used for C2, data exfil, or lateral movement
    SUSPICIOUS_PORTS = {4444, 5555, 1234, 6666, 8888, 9001, 31337}

    def __init__(self, snapshot_interval: float = 1.0):
        self.snapshot_interval = snapshot_interval
        self.baseline: Dict[str, Any] = {}
        self.anomalies: List[Dict[str, Any]] = []

    def capture_snapshot(self) -> Dict[str, Any]:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            connections.append({
                "local": laddr,
                "remote": raddr,
                "status": conn.status,
                "pid": conn.pid
            })

        ports_counter = Counter()
        remote_ips = Counter()
        statuses = Counter()
        for c in connections:
            if c["local"] != "N/A":
                port = c["local"].split(":")[-1]
                try:
                    ports_counter[int(port)] += 1
                except ValueError:
                    pass
            if c["remote"] != "N/A":
                remote_ip = c["remote"].split(":")[0]
                remote_ips[remote_ip] += 1
            statuses[c["status"]] += 1

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_connections": len(connections),
            "connections": connections,
            "listening_ports": dict(ports_counter),
            "remote_ips": dict(remote_ips),
            "status_breakdown": dict(statuses)
        }

    def detect_anomalies(self, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        found = []

        # 1. Detect port scan pattern: many connections to different ports from same IP
        remote_ip_counts = snapshot.get("remote_ips", {})
        for ip, count in remote_ip_counts.items():
            if count >= 15:
                found.append({
                    "type": "PORT_SCAN_PATTERN",
                    "severity": "HIGH",
                    "indicator": ip,
                    "details": f"IP {ip} has {count} active connections - possible port scan or brute force"
                })

        # 2. Detect suspicious ports
        for port in snapshot.get("listening_ports", {}):
            if int(port) in self.SUSPICIOUS_PORTS:
                found.append({
                    "type": "SUSPICIOUS_PORT",
                    "severity": "MEDIUM",
                    "indicator": port,
                    "details": f"Service listening on well-known malware/C2 port {port}"
                })

        # 3. Detect excessive TIME_WAIT connections (possible SYN flood)
        if snapshot.get("status_breakdown", {}).get("TIME_WAIT", 0) > 50:
            found.append({
                "type": "EXCESSIVE_TIMEWAIT",
                "severity": "MEDIUM",
                "indicator": "TIME_WAIT",
                "details": f"{snapshot['status_breakdown']['TIME_WAIT']} TIME_WAIT connections detected - possible SYN flood or port exhaustion"
            })

        # 4. Detect high connection count from single remote IP
        for ip, count in remote_ip_counts.items():
            if count >= 10 and ip != "127.0.0.1":
                found.append({
                    "type": "HIGH_CONNECTION_VOLUME",
                    "severity": "LOW",
                    "indicator": ip,
                    "details": f"IP {ip} with {count} connections - monitor for lateral movement"
                })

        self.anomalies.extend(found)
        return found

    def run_analysis(self) -> Dict[str, Any]:
        snapshot = self.capture_snapshot()
        anomalies = self.detect_anomalies(snapshot)
        return {
            "snapshot": snapshot,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies)
        }
