import json
import urllib.request
from typing import Dict, Any, Optional

class IPIntelligence:
    """
    Enriches scan results with Whois data and geolocation
    for discovered IP addresses.
    """

    def __init__(self):
        self.cache = {}

    def geolocate(self, ip: str) -> Optional[Dict[str, Any]]:
        if ip in self.cache and "geo" in self.cache[ip]:
            return self.cache[ip]["geo"]

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
            req = urllib.request.Request(url, headers={"User-Agent": "Bifrost/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    geo = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "lat": data.get("lat", 0),
                        "lon": data.get("lon", 0),
                        "timezone": data.get("timezone", ""),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "as": data.get("as", "Unknown"),
                        "mobile": data.get("mobile", False),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False)
                    }
                    if ip not in self.cache:
                        self.cache[ip] = {}
                    self.cache[ip]["geo"] = geo
                    return geo
        except Exception:
            pass
        return None

    def whois_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        if ip in self.cache and "whois" in self.cache[ip]:
            return self.cache[ip]["whois"]

        try:
            url = f"https://rdap.org/ip/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "Bifrost/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                whois = {
                    "name": data.get("name", ip),
                    "handle": data.get("handle", ""),
                    "start_address": data.get("startAddress", ip),
                    "end_address": data.get("endAddress", ip),
                    "ip_version": data.get("ipVersion", []),
                    "country": "",
                    "status": data.get("status", []),
                    "remarks": []
                }

                for entity in data.get("entities", []):
                    for vc in entity.get("vcardArray", [])[1] if isinstance(entity.get("vcardArray"), list) else []:
                        if vc[0] == "adr":
                            whois["country"] = vc[3][-1] if len(vc[3]) > 1 else ""

                for remark in data.get("remarks", []):
                    whois["remarks"].append(remark.get("description", ""))

                if ip not in self.cache:
                    self.cache[ip] = {}
                self.cache[ip]["whois"] = whois
                return whois
        except Exception:
            pass
        return None

    KNOWN_VULNS = [
        {"patterns": ["openssh 7.", "openssh_7."], "cve": "CVE-2018-15473", "severity": "MEDIUM", "description": "OpenSSH 7.x User Enumeration vulnerability"},
        {"patterns": ["openssh 8.5", "openssh_8.5"], "cve": "CVE-2021-41617", "severity": "MEDIUM", "description": "OpenSSH privilege escalation in helper process"},
        {"patterns": ["vsftpd 2.3.4", "vsftpd_2.3.4"], "cve": "CVE-2011-2523", "severity": "CRITICAL", "description": "vsftpd 2.3.4 Backdoor Command Execution"},
        {"patterns": ["apache 2.4.49", "apache_2.4.49"], "cve": "CVE-2021-41773", "severity": "CRITICAL", "description": "Apache HTTP Server Path Traversal & RCE"},
        {"patterns": ["apache 2.4.50", "apache_2.4.50"], "cve": "CVE-2021-42013", "severity": "CRITICAL", "description": "Apache HTTP Server Path Traversal & RCE"},
        {"patterns": ["log4j"], "cve": "CVE-2021-44228", "severity": "CRITICAL", "description": "Apache Log4j2 Remote Code Execution (Log4Shell)"},
    ]

    def vulnerability_lookup(self, banner: str) -> list:
        if not banner:
            return []
        banner_lower = banner.lower()
        vulns = []
        for v in self.KNOWN_VULNS:
            if any(p in banner_lower for p in v["patterns"]):
                vulns.append({
                    "cve": v["cve"],
                    "severity": v["severity"],
                    "description": v["description"]
                })
        return vulns

    def enrich_scan_results(self, scan_results: list) -> list:
        enriched = []
        for result in scan_results:
            ip = result.get("ip", "")
            if not ip:
                enriched.append(result)
                continue

            geo = self.geolocate(ip)
            whois = self.whois_lookup(ip)

            vulnerabilities = []
            for open_port in result.get("open_ports", []):
                banner = open_port.get("banner", "")
                if banner:
                    found = self.vulnerability_lookup(banner)
                    if found:
                        vulnerabilities.extend(found)

            enriched_entry = dict(result)
            enriched_entry["geo"] = geo
            enriched_entry["whois"] = whois
            enriched_entry["vulnerabilities"] = vulnerabilities
            enriched.append(enriched_entry)

        return enriched

    def get_threat_tags(self, geo: Dict[str, Any]) -> list:
        tags = []
        if geo:
            if geo.get("proxy"):
                tags.append("PROXY/VPN")
            if geo.get("hosting"):
                tags.append("HOSTING/DATACENTER")
            if geo.get("mobile"):
                tags.append("MOBILE")
            if geo.get("country_code") in ["RU", "CN", "KP", "IR"]:
                tags.append("HIGH_RISK_COUNTRY")
        return tags
