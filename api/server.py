from fastapi import FastAPI
from pydantic import BaseModel
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

class ScanRequest(BaseModel):
    host: str
    ports: Optional[List[int]] = None
    common: Optional[bool] = True

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
def scan_target(payload: ScanRequest):
    if payload.ports:
        return scanner.scan(payload.host, payload.ports)
    return scanner.scan_common(payload.host)

@app.get("/api/v1/analyze")
def analyze_traffic():
    return analyzer.run_analysis()

@app.post("/api/v1/report")
def generate_report(payload: ReportRequest):
    path = reporter.generate_report(
        scan_result=payload.scan_result,
        analysis_result=payload.analysis_result,
        encrypt_password=payload.encrypt_password
    )
    return {"status": "success", "report_path": path}

@app.get("/api/v1/full")
def full_analysis(host: str = "127.0.0.1"):
    scan = scanner.scan_common(host)
    analysis = analyzer.run_analysis()
    report = reporter.generate_report(scan_result=scan, analysis_result=analysis)
    return {
        "scan": scan,
        "analysis": analysis,
        "report_path": report
    }
