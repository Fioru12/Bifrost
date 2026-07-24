import ipaddress
import socket
import concurrent.futures
import time
from typing import Dict, Any, List

class LANDiscovery:
    """
    Enterprise LAN Asset Discovery & Network Inventory engine.
    Performs multi-threaded subnet sweeps, host reachability checks,
    reverse DNS resolution, and core port fingerprinting.
    """

    def __init__(self, timeout: float = 0.5):
        self.timeout = timeout
        # Common management/service ports to probe for host liveness
        self.probe_ports = [80, 443, 445, 135, 22, 3389, 53, 21]

    def _check_host(self, ip: str) -> Dict[str, Any]:
        live = False
        open_ports = []
        hostname = "Unknown"

        # Check reachability via TCP probe on common ports
        for port in self.probe_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    live = True
                    open_ports.append(port)
            except Exception:
                pass

        if not live:
            return None

        # Attempt reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unresolved"

        return {
            "ip": ip,
            "hostname": hostname,
            "status": "online",
            "open_ports": open_ports,
            "device_type": self._guess_device_type(open_ports)
        }

    def _guess_device_type(self, open_ports: List[int]) -> str:
        if 445 in open_ports or 135 in open_ports:
            return "Windows Server / Workstation"
        elif 22 in open_ports and 80 not in open_ports:
            return "Linux / Unix Server"
        elif 3389 in open_ports:
            return "Windows RDP Host"
        elif 80 in open_ports or 443 in open_ports:
            return "Web Server / Gateway"
        else:
            return "Network Device / IoT"

    def sweep_subnet(self, subnet_str: str = "192.168.1.0/24", max_workers: int = 50) -> Dict[str, Any]:
        start_time = time.time()
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
        except Exception as e:
            return {"error": str(e), "hosts": []}

        hosts = []
        ip_list = [str(ip) for ip in net.hosts()]

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self._check_host, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(future_to_ip):
                res = future.result()
                if res:
                    hosts.append(res)

        duration = round(time.time() - start_time, 2)
        return {
            "subnet": subnet_str,
            "total_scanned": len(ip_list),
            "live_hosts_count": len(hosts),
            "scan_duration_sec": duration,
            "hosts": sorted(hosts, key=lambda x: [int(n) for n in x["ip"].split(".")])
        }
