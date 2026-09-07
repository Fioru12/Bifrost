import pytest
from core.intel import IPIntelligence

def test_vulnerability_lookup_detects_vsftpd_backdoor():
    intel = IPIntelligence()
    vulns = intel.vulnerability_lookup("220 (vsFTPd 2.3.4)")
    assert len(vulns) == 1
    assert vulns[0]["cve"] == "CVE-2011-2523"
    assert vulns[0]["severity"] == "CRITICAL"

def test_enrich_scan_results_adds_vulnerabilities():
    intel = IPIntelligence()
    scan_data = [
        {
            "ip": "192.168.1.100",
            "open_ports": [
                {"port": 21, "banner": "220 (vsFTPd 2.3.4)"},
                {"port": 22, "banner": "SSH-2.0-OpenSSH_7.2p1"}
            ]
        }
    ]
    enriched = intel.enrich_scan_results(scan_data)
    assert len(enriched) == 1
    vulnerabilities = enriched[0]["vulnerabilities"]
    assert len(vulnerabilities) == 2
    cves = {v["cve"] for v in vulnerabilities}
    assert "CVE-2011-2523" in cves
    assert "CVE-2018-15473" in cves
