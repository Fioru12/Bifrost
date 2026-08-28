import socket
import time
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common service signatures for port identification
SERVICE_DB = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB"
}

class PortScanner:
    """
    TCP port scanner with service fingerprinting.
    Uses threaded connect scan for speed and identifies common services.
    """

    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    # Ports where the service waits for the client to speak first, so a
    # purely passive recv() will time out with nothing captured. For these
    # we send a minimal active probe before giving up.
    HTTP_LIKE_PORTS = {80, 8080, 8000}

    def _resolve(self, host: str, port: int):
        """Resolve host/port via getaddrinfo so we pick the correct address
        family (IPv4 or IPv6) instead of assuming AF_INET. Returns the first
        (family, sockaddr) tuple, or None if resolution fails."""
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return None
        if not infos:
            return None
        family, _socktype, _proto, _canonname, sockaddr = infos[0]
        return family, sockaddr

    def _scan_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        resolved = self._resolve(host, port)
        if resolved is None:
            return None
        family, sockaddr = resolved

        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start = time.time()
            result = sock.connect_ex(sockaddr)
            elapsed = round((time.time() - start) * 1000, 2)

            if result == 0:
                service = SERVICE_DB.get(port, "unknown")
                banner = self._grab_banner(sock, port)
                sock.close()
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "latency_ms": elapsed,
                    "banner": banner
                }
            sock.close()
        except (socket.timeout, OSError):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    def _grab_banner(self, sock: socket.socket, port: Optional[int] = None) -> Optional[str]:
        # Passive attempt: many services (SSH, FTP, SMTP...) send a greeting
        # banner unprompted.
        try:
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                return banner[:200]
        except Exception:
            pass

        # Active fallback: HTTP(-like) services stay silent until spoken to.
        # Send a minimal HEAD request and retry the read once with a short
        # timeout. Other protocols remain passive-only for now (see README).
        if port in self.HTTP_LIKE_PORTS:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                sock.settimeout(0.5)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner[:200] if banner else None
            except Exception:
                return None

        return None

    def scan(self, host: str, ports: List[int]) -> Dict[str, Any]:
        open_ports = []
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_port, host, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        scan_duration = round(time.time() - start_time, 2)

        return {
            "host": host,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "open_count": len(open_ports),
            "scan_duration_sec": scan_duration
        }

    def scan_common(self, host: str) -> Dict[str, Any]:
        common_ports = list(SERVICE_DB.keys())
        return self.scan(host, common_ports)
