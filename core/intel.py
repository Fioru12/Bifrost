import json
import os
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
        {"patterns": ["openssh 6.", "openssh_6."], "cve": "CVE-2016-0777", "severity": "MEDIUM", "description": "OpenSSH 5.4-7.1 roaming info leak (client)"},
        {"patterns": ["openssh 8.5", "openssh_8.5"], "cve": "CVE-2021-41617", "severity": "MEDIUM", "description": "OpenSSH privilege escalation in helper process"},
        {"patterns": ["vsftpd 2.3.4", "vsftpd_2.3.4"], "cve": "CVE-2011-2523", "severity": "CRITICAL", "description": "vsftpd 2.3.4 Backdoor Command Execution"},
        {"patterns": ["proftpd 1.3.3", "proftpd_1.3.3"], "cve": "CVE-2010-4221", "severity": "CRITICAL", "description": "ProFTPD 1.3.3c Backdoor Command Execution"},
        {"patterns": ["apache 2.4.49", "apache_2.4.49"], "cve": "CVE-2021-41773", "severity": "CRITICAL", "description": "Apache HTTP Server Path Traversal & RCE"},
        {"patterns": ["apache 2.4.50", "apache_2.4.50"], "cve": "CVE-2021-42013", "severity": "CRITICAL", "description": "Apache HTTP Server Path Traversal & RCE"},
        {"patterns": ["microsoft-iis 6.0", "iis 6.0", "iis/6.0"], "cve": "CVE-2017-7269", "severity": "CRITICAL", "description": "IIS 6.0 WebDAV Buffer Overflow RCE"},
        {"patterns": ["openssl 1.0.1", "openssl/1.0.1"], "cve": "CVE-2014-0160", "severity": "CRITICAL", "description": "OpenSSL Heartbleed information disclosure"},
        {"patterns": ["samba 3.", "samba 4.0", "samba 4.1", "samba 4.2", "samba 4.3", "samba 4.4", "samba 4.5", "samba 4.6"],
         "cve": "CVE-2017-7494", "severity": "CRITICAL", "description": "Samba is_known_pipename RCE (SambaCry)"},
        {"patterns": ["php/8.1.0-dev", "php 8.1.0-dev"], "cve": "CVE-2021-21706", "severity": "CRITICAL", "description": "PHP 8.1.0-dev Backdoor Command Execution"},
        {"patterns": ["log4j"], "cve": "CVE-2021-44228", "severity": "CRITICAL", "description": "Apache Log4j2 Remote Code Execution (Log4Shell)"},
    ]

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

    def fetch_nvd_cvss(self, cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Ritorna {cvss, severity} live da NVD API v2 per un CVE, o None.

        Best-effort puro: rate-limit (403/429), rete giu', CVE sconosciuto o
        JSON inatteso -> None, mai un'eccezione. Risultati in cache per
        sessione. `api_key` opzionale (env NVD_API_KEY, rate-limit piu' alto).
        """
        if not cve_id:
            return None
        cve_id = cve_id.strip().upper()
        cached = self.cache.get("nvd", {}).get(cve_id)
        if cached is not None:
            return cached
        try:
            url = f"{self.NVD_API_URL}?cveId={cve_id}"
            headers = {"User-Agent": "Bifrost/1.0"}
            if api_key:
                headers["apiKey"] = api_key
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            metrics = (data.get("vulnerabilities") or [{}])[0].get("cve", {}).get("metrics", {})
            cvss_data = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key) or []
                if entries and isinstance(entries[0].get("cvssData"), dict):
                    cvss_data = entries[0]["cvssData"]
                    break
            if not cvss_data:
                result = None
            else:
                result = {
                    "cvss": cvss_data.get("baseScore"),
                    "severity": (cvss_data.get("baseSeverity") or "").upper() or None,
                }
        except Exception:
            result = None
        self.cache.setdefault("nvd", {})[cve_id] = result
        return result

    def enrich_vulns_with_nvd(self, vulns: list, api_key: Optional[str] = None) -> list:
        """Aggiunge `cvss` live a ogni dict vuln (chiave assente se NVD non risponde)."""
        if api_key is None:
            api_key = os.environ.get("NVD_API_KEY")
        enriched = []
        for v in vulns:
            entry = dict(v)
            live = self.fetch_nvd_cvss(v.get("cve", ""), api_key=api_key)
            if live and live.get("cvss") is not None:
                entry["cvss"] = live["cvss"]
                if live.get("severity"):
                    entry["nvd_severity"] = live["severity"]
            enriched.append(entry)
        return enriched

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
