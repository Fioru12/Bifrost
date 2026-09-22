import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.intel import IPIntelligence


def _fake_nvd_response(cvss_score=9.8, severity="CRITICAL"):
    payload = {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": [
        {"cvssData": {"baseScore": cvss_score, "baseSeverity": severity}}]}}}]}
    data = json.dumps(payload).encode()

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return data

    return FakeResp()


def test_known_vulns_extended():
    intel = IPIntelligence()
    cases = {
        "OpenSSL/1.0.1f": "CVE-2014-0160",
        "220 Samba 4.3.11-Ubuntu": "CVE-2017-7494",
        "220 ProFTPD 1.3.3c Server": "CVE-2010-4221",
        "Server: Microsoft-IIS/6.0": "CVE-2017-7269",
        "X-Powered-By: PHP/8.1.0-dev": "CVE-2021-21706",
        "SSH-2.0-OpenSSH_6.6p1": "CVE-2016-0777",
        "220 (vsFTPd 2.3.4)": "CVE-2011-2523",  # regressione: vecchie entry intatte
    }
    for banner, cve in cases.items():
        cves = {v["cve"] for v in intel.vulnerability_lookup(banner)}
        assert cve in cves, f"{banner} -> {cves}"


def test_fetch_nvd_cvss_parses_and_caches(monkeypatch):
    import core.intel as intel_mod
    calls = {"n": 0}

    def fake_urlopen(req, timeout=10):
        calls["n"] += 1
        assert "cveId=CVE-2011-2523" in req.full_url
        return _fake_nvd_response(9.8, "CRITICAL")

    monkeypatch.setattr(intel_mod.urllib.request, "urlopen", fake_urlopen)
    intel = IPIntelligence()
    res = intel.fetch_nvd_cvss("cve-2011-2523")
    assert res == {"cvss": 9.8, "severity": "CRITICAL"}
    assert intel.fetch_nvd_cvss("CVE-2011-2523") == res  # cache: nessuna 2a chiamata
    assert calls["n"] == 1


def test_fetch_nvd_failure_returns_none(monkeypatch):
    import core.intel as intel_mod

    def boom(req, timeout=10):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

    monkeypatch.setattr(intel_mod.urllib.request, "urlopen", boom)
    assert IPIntelligence().fetch_nvd_cvss("CVE-2011-2523") is None


def test_enrich_vulns_with_nvd_adds_cvss(monkeypatch):
    intel = IPIntelligence()
    monkeypatch.setattr(intel, "fetch_nvd_cvss", lambda cve, api_key=None: {"cvss": 7.5, "severity": "HIGH"})
    out = intel.enrich_vulns_with_nvd([{"cve": "CVE-2018-15473", "severity": "MEDIUM", "description": "x"}])
    assert out[0]["cvss"] == 7.5
    assert out[0]["nvd_severity"] == "HIGH"
    assert out[0]["severity"] == "MEDIUM"  # severita' locale invariata


def test_enrich_vulns_nvd_down_keeps_local(monkeypatch):
    intel = IPIntelligence()
    monkeypatch.setattr(intel, "fetch_nvd_cvss", lambda cve, api_key=None: None)
    vulns = [{"cve": "CVE-2011-2523", "severity": "CRITICAL", "description": "x"}]
    assert intel.enrich_vulns_with_nvd(vulns) == vulns
