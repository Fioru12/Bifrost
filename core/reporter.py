import os
import json
import base64
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptedReporter:
    """
    Generates network security reports in Markdown and optionally encrypts them
    using AES-128 (Fernet symmetric encryption) with a password-derived key.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _derive_key(self, password: str) -> bytes:
        salt = b"bifrost-salt-v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_content(self, content: str, password: str) -> bytes:
        key = self._derive_key(password)
        f = Fernet(key)
        return f.encrypt(content.encode())

    def decrypt_content(self, encrypted: bytes, password: str) -> str:
        key = self._derive_key(password)
        f = Fernet(key)
        return f.decrypt(encrypted).decode()

    def generate_report(
        self,
        scan_result: Optional[Dict[str, Any]] = None,
        analysis_result: Optional[Dict[str, Any]] = None,
        encrypt_password: Optional[str] = None
    ) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "# Bifrost Network Security Report",
            "",
            f"**Generated:** {timestamp}",
            f"**Engine:** Bifrost Network Telemetry & Port Analysis",
            "",
            "---",
            ""
        ]

        # Port scan section
        if scan_result:
            lines.extend([
                "## 1. Port Scan Results",
                "",
                f"- **Target Host:** `{scan_result.get('host', 'N/A')}`",
                f"- **Ports Scanned:** `{scan_result.get('ports_scanned', 0)}`",
                f"- **Open Ports Found:** `{scan_result.get('open_count', 0)}`",
                f"- **Scan Duration:** `{scan_result.get('scan_duration_sec', 0)}s`",
                ""
            ])

            if scan_result.get("open_ports"):
                lines.extend([
                    "| Port | State | Service | Latency | Banner |",
                    "|:---:|:---:|:---|:---:|:---|"
                ])
                for p in scan_result["open_ports"]:
                    banner = (p.get("banner") or "-")[:50]
                    lines.append(
                        f"| {p['port']} | {p['state']} | {p['service']} | {p['latency_ms']}ms | `{banner}` |"
                    )
                lines.append("")
            else:
                lines.append("No open ports detected.\n")

        # Traffic analysis section
        if analysis_result:
            snapshot = analysis_result.get("snapshot", {})
            anomalies = analysis_result.get("anomalies", [])

            lines.extend([
                "## 2. Live Traffic Analysis",
                "",
                f"- **Total Active Connections:** `{snapshot.get('total_connections', 0)}`",
                f"- **Unique Remote IPs:** `{len(snapshot.get('remote_ips', {}))}`",
                f"- **Anomalies Detected:** `{analysis_result.get('anomaly_count', 0)}`",
                ""
            ])

            if anomalies:
                lines.extend([
                    "### Anomalies",
                    ""
                ])
                for a in anomalies:
                    lines.extend([
                        f"- **[{a['severity']}]** `{a['type']}`",
                        f"  - Indicator: `{a['indicator']}`",
                        f"  - {a['details']}",
                        ""
                    ])
            else:
                lines.append("No anomalies detected in current traffic snapshot.\n")

        # Recommendations
        lines.extend([
            "---",
            "",
            "## 3. Recommendations",
            ""
        ])

        if scan_result and scan_result.get("open_count", 0) > 0:
            lines.append("- Review open ports and ensure only necessary services are exposed")
            lines.append("- Verify service versions against known vulnerability databases")
        if analysis_result and analysis_result.get("anomaly_count", 0) > 0:
            lines.append("- Investigate flagged anomalies and correlate with Heimdall alerts")
            lines.append("- Consider isolating hosts with suspicious connection patterns")
        if not scan_result and not analysis_result:
            lines.append("- No data to analyze. Run a scan or traffic analysis first.")

        report_content = "\n".join(lines)
        filename = f"Bifrost_Report_{timestamp.replace(':', '-').replace(' ', '_')}"

        # Save plain text
        md_path = os.path.join(self.output_dir, f"{filename}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        # Save encrypted version if password provided
        enc_path = None
        if encrypt_password:
            encrypted = self.encrypt_content(report_content, encrypt_password)
            enc_path = os.path.join(self.output_dir, f"{filename}.enc")
            with open(enc_path, "wb") as f:
                f.write(encrypted)

        return md_path
