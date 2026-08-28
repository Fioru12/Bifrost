import ipaddress
import os
import re
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any
from core.scanner import PortScanner
from core.analyzer import TrafficAnalyzer
from core.reporter import EncryptedReporter

app = FastAPI(
    title="Bifrost Network Security API",
    description="Port scanning, traffic analysis, and encrypted telemetry reports",
    version="1.0.0"
)

scanner = PortScanner()
analyzer = TrafficAnalyzer()
reporter = EncryptedReporter()

# Maximum number of ports allowed in a single scan request, to avoid the API
# being abused as an unbounded port-scanner-as-a-service.
MAX_PORTS_PER_REQUEST = 1024

# Simple hostname/IP validation: either a valid IP address, or a hostname made
# up of alphanumerics, dots and dashes.
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]+$")

API_KEY_ENV_VAR = "BIFROST_API_KEY"
_API_KEY = os.environ.get(API_KEY_ENV_VAR)
if not _API_KEY:
    _API_KEY = secrets.token_urlsafe(32)
    print(
        f"[WARNING] no {API_KEY_ENV_VAR} set, using generated key: {_API_KEY}\n"
        f"[WARNING] set the {API_KEY_ENV_VAR} environment variable to use a stable key."
    )


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency that enforces the X-API-Key header on protected endpoints."""
    if not x_api_key or not secrets.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Provide it via the X-API-Key header.",
        )


def _validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("host must not be empty")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _HOSTNAME_RE.match(host):
        return host
    raise ValueError(f"invalid host: {host!r}")


class ScanRequest(BaseModel):
    host: str
    ports: Optional[List[int]] = None
    common: Optional[bool] = True

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        try:
            return _validate_host(value)
        except ValueError as exc:
            raise ValueError(str(exc))

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: Optional[List[int]]) -> Optional[List[int]]:
        if value is None:
            return value
        if len(value) == 0:
            raise ValueError("ports must not be empty; omit the field to scan common ports instead")
        if len(value) > MAX_PORTS_PER_REQUEST:
            raise ValueError(f"too many ports requested: max {MAX_PORTS_PER_REQUEST} per request")
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port number: {port}")
        return value

class ReportRequest(BaseModel):
    scan_result: Optional[Dict[str, Any]] = None
    analysis_result: Optional[Dict[str, Any]] = None
    encrypt_password: Optional[str] = None

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Bifrost Network Security API",
        "version": "1.0.0",
        "endpoints": [
            "/api/v1/scan",
            "/api/v1/analyze",
            "/api/v1/report",
            "/api/v1/full"
        ]
    }

@app.post("/api/v1/scan")
def scan_target(payload: ScanRequest, _: None = Depends(require_api_key)):
    if payload.ports:
        return scanner.scan(payload.host, payload.ports)
    return scanner.scan_common(payload.host)

@app.get("/api/v1/analyze")
def analyze_traffic(_: None = Depends(require_api_key)):
    return analyzer.run_analysis()

@app.post("/api/v1/report")
def generate_report(payload: ReportRequest, _: None = Depends(require_api_key)):
    path = reporter.generate_report(
        scan_result=payload.scan_result,
        analysis_result=payload.analysis_result,
        encrypt_password=payload.encrypt_password
    )
    return {"status": "success", "report_path": path}

@app.get("/api/v1/full")
def full_analysis(host: str = "127.0.0.1", _: None = Depends(require_api_key)):
    try:
        host = _validate_host(host)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    scan = scanner.scan_common(host)
    analysis = analyzer.run_analysis()
    report = reporter.generate_report(scan_result=scan, analysis_result=analysis)
    return {
        "scan": scan,
        "analysis": analysis,
        "report_path": report
    }
