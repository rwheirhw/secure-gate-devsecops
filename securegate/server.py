"""SecureGate REST API & Dashboard Server.

Exposes assessment, inspection, baseline, and drift detection capabilities
over HTTP, reusing existing SecureGate core modules.
"""

import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .analyzer import Analyzer
from .baseline import BaselineStore, DriftDetector
from .inspectors.kubernetes import KubernetesInspector
from .json_reporter import JsonReporter
from .models import ScanResult
from .parser import TrivyParser
from .policy import PolicyEngine
from .risk import RiskEngine

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = Path(__file__).resolve().parent / "web"


class SecureGateHandler(BaseHTTPRequestHandler):
    """HTTP request handler providing REST API endpoints and static UI."""

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self.send_response(HTTPStatus.OK)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Handle GET requests for API endpoints and static assets."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self._send_json(
                {
                    "status": "ok",
                    "version": __version__,
                    "system": "SecureGate DevSecOps Assurance",
                }
            )
            return

        if path == "/api/reports":
            self._handle_list_reports()
            return

        if path.startswith("/api/reports/"):
            filename = unquote(path[len("/api/reports/") :])
            self._handle_get_report(filename)
            return

        if path == "/api/baselines":
            self._handle_list_baselines()
            return

        if path.startswith("/api/baselines/"):
            filename = unquote(path[len("/api/baselines/") :])
            self._handle_get_baseline(filename)
            return

        if path == "/api/samples":
            self._handle_get_samples()
            return

        # Serve static web dashboard
        self._serve_static(path)

    def do_POST(self):
        """Handle POST requests for assessment and drift analysis."""
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/assess":
            self._handle_assess(body)
            return

        if path == "/api/inspect":
            self._handle_inspect(body)
            return

        if path == "/api/baseline/save":
            self._handle_save_baseline(body)
            return

        if path == "/api/drift":
            self._handle_detect_drift(body)
            return

        self._send_error(HTTPStatus.NOT_FOUND, f"Endpoint {path} not found")

    # -------------------------------------------------------------------------
    # API Endpoint Handlers
    # -------------------------------------------------------------------------

    def _handle_assess(self, body: dict[str, Any]):
        """Perform combined assessment of manifest and container scan."""
        try:
            manifest_yaml = body.get("manifest_yaml", "")
            manifest_file = body.get("manifest_file")
            report_file = body.get("report_file", "reports/scan.json")
            policy_file = body.get("policy_file", "config/policy.yaml")

            # 1. Inspect K8s manifest (inline or file)
            if manifest_yaml.strip():
                inspector = KubernetesInspector(yaml_content=manifest_yaml)
                target_name = "inline-manifest.yaml"
            elif manifest_file:
                target_path = ROOT_DIR / manifest_file
                inspector = KubernetesInspector(str(target_path))
                target_name = str(manifest_file)
            else:
                self._send_error(HTTPStatus.BAD_REQUEST, "Missing manifest_yaml or manifest_file")
                return

            k8s_findings = inspector.inspect()

            # 2. Parse Trivy report if file exists
            trivy_results = []
            if report_file:
                rep_path = ROOT_DIR / report_file
                if rep_path.is_file():
                    parser = TrivyParser(str(rep_path))
                    trivy_results = parser.parse()

            all_results = list(trivy_results) + [
                ScanResult(target=target_name, findings=k8s_findings)
            ]

            analyzer = Analyzer(all_results)

            # 3. Policy evaluation
            pol_path = ROOT_DIR / policy_file
            if not pol_path.exists():
                pol_path = ROOT_DIR / "config/policy.json"

            policy_engine = PolicyEngine(str(pol_path))
            decision = policy_engine.evaluate(analyzer.all_findings())

            # 4. Transparent Risk Calculation
            risk = RiskEngine().assess(analyzer.all_findings())

            # 5. Generate structured report
            report = JsonReporter.generate(
                decision=decision,
                analyzer=analyzer,
                risk=risk,
                metadata={
                    "mode": "api_assess",
                    "report_file": str(report_file),
                    "policy_file": str(policy_file),
                },
            )

            # Enrich response with posture and explicit rule details
            report["posture"] = inspector.posture()
            report["risk"]["explanation"] = {
                "rule_priority": "Mandatory BLOCK rules take absolute precedence over numerical scores.",
                "formula": "Total Risk = min(100, Artifact Risk [max 40] + Deployment Risk [max 45] + Drift Risk [max 30])",
            }

            self._send_json(report)

        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_inspect(self, body: dict[str, Any]):
        """Inspect K8s manifest alone."""
        try:
            manifest_yaml = body.get("manifest_yaml", "")
            policy_file = body.get("policy_file", "config/policy.yaml")

            if not manifest_yaml.strip():
                self._send_error(HTTPStatus.BAD_REQUEST, "manifest_yaml is required")
                return

            inspector = KubernetesInspector(yaml_content=manifest_yaml)
            k8s_findings = inspector.inspect()

            analyzer = Analyzer([ScanResult(target="inline.yaml", findings=k8s_findings)])

            pol_path = ROOT_DIR / policy_file
            if not pol_path.exists():
                pol_path = ROOT_DIR / "config/policy.json"

            policy_engine = PolicyEngine(str(pol_path))
            decision = policy_engine.evaluate(analyzer.all_findings())
            risk = RiskEngine().assess(analyzer.all_findings())

            report = JsonReporter.generate(
                decision=decision,
                analyzer=analyzer,
                risk=risk,
                metadata={"mode": "api_inspect"},
            )
            report["posture"] = inspector.posture()
            self._send_json(report)

        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_save_baseline(self, body: dict[str, Any]):
        """Save a passing manifest as an approved baseline."""
        try:
            manifest_yaml = body.get("manifest_yaml", "")
            baseline_name = body.get("name", "security-baseline.json")

            if not manifest_yaml.strip():
                self._send_error(HTTPStatus.BAD_REQUEST, "manifest_yaml is required")
                return

            inspector = KubernetesInspector(yaml_content=manifest_yaml)
            findings = inspector.inspect()

            analyzer = Analyzer([ScanResult(target="inline.yaml", findings=findings)])
            policy_engine = PolicyEngine(str(ROOT_DIR / "config/policy.json"))
            decision = policy_engine.evaluate(analyzer.all_findings())
            risk = RiskEngine().assess(analyzer.all_findings())

            if decision.decision == "BLOCK":
                self._send_error(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    "Cannot establish baseline: Manifest violates policy and is BLOCKED.",
                )
                return

            baseline_path = ROOT_DIR / "baselines" / baseline_name
            store = BaselineStore()
            saved_path = store.save(
                output_path=str(baseline_path),
                manifest=body.get("manifest_name", "web-submission.yaml"),
                posture=inspector.posture(),
                risk=risk,
            )

            self._send_json(
                {
                    "status": "created",
                    "filename": baseline_name,
                    "path": str(saved_path),
                    "approved_posture": inspector.posture(),
                }
            )

        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_detect_drift(self, body: dict[str, Any]):
        """Detect posture drift against a saved baseline."""
        try:
            manifest_yaml = body.get("manifest_yaml", "")
            baseline_file = body.get("baseline_file", "security-baseline.json")

            if not manifest_yaml.strip():
                self._send_error(HTTPStatus.BAD_REQUEST, "manifest_yaml is required")
                return

            baseline_path = ROOT_DIR / "baselines" / baseline_file
            if not baseline_path.exists():
                self._send_error(
                    HTTPStatus.NOT_FOUND, f"Baseline {baseline_file} does not exist"
                )
                return

            store = BaselineStore()
            approved_data = store.load(str(baseline_path))

            inspector = KubernetesInspector(yaml_content=manifest_yaml)
            current_posture = inspector.posture()

            detector = DriftDetector()
            drift_events = detector.detect(approved_data["posture"], current_posture)
            findings = detector.findings_for(drift_events)

            analyzer = Analyzer([ScanResult(target="drift-check", findings=findings)])
            policy_engine = PolicyEngine(str(ROOT_DIR / "config/policy.json"))
            decision = policy_engine.evaluate(analyzer.all_findings())
            risk = RiskEngine().assess(analyzer.all_findings())

            self._send_json(
                {
                    "decision": decision.decision,
                    "drift_count": len(drift_events),
                    "drift_events": [
                        {
                            "id": event.id,
                            "resource": event.resource,
                            "field": event.field,
                            "approved": event.approved_value,
                            "current": event.current_value,
                            "severity": event.severity,
                            "message": event.message,
                        }
                        for event in drift_events
                    ],
                    "risk": {
                        "drift_risk": risk.drift_risk,
                        "total_risk": risk.total_risk,
                        "level": risk.level,
                    },
                    "approved_timestamp": approved_data.get("approved_at"),
                }
            )

        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_list_reports(self):
        """List reports in reports/ directory."""
        reports_dir = ROOT_DIR / "reports"
        files = []
        if reports_dir.exists():
            for p in sorted(reports_dir.glob("*.json")):
                stat = p.stat()
                files.append(
                    {
                        "filename": p.name,
                        "size_bytes": stat.st_size,
                        "modified_at": stat.st_mtime,
                    }
                )
        self._send_json({"reports": files})

    def _handle_get_report(self, filename: str):
        """Return content of a specific report file."""
        report_path = (ROOT_DIR / "reports" / filename).resolve()
        if not str(report_path).startswith(str((ROOT_DIR / "reports").resolve())):
            self._send_error(HTTPStatus.FORBIDDEN, "Invalid path")
            return
        if not report_path.exists():
            self._send_error(HTTPStatus.NOT_FOUND, f"Report {filename} not found")
            return
        try:
            with report_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self._send_json(data)
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_list_baselines(self):
        """List saved baseline files."""
        baselines_dir = ROOT_DIR / "baselines"
        files = []
        if baselines_dir.exists():
            for p in sorted(baselines_dir.glob("*.json")):
                stat = p.stat()
                files.append(
                    {
                        "filename": p.name,
                        "size_bytes": stat.st_size,
                        "modified_at": stat.st_mtime,
                    }
                )
        self._send_json({"baselines": files})

    def _handle_get_baseline(self, filename: str):
        """Return content of a specific baseline."""
        path = (ROOT_DIR / "baselines" / filename).resolve()
        if not str(path).startswith(str((ROOT_DIR / "baselines").resolve())):
            self._send_error(HTTPStatus.FORBIDDEN, "Invalid path")
            return
        if not path.exists():
            self._send_error(HTTPStatus.NOT_FOUND, f"Baseline {filename} not found")
            return
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self._send_json(data)
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_get_samples(self):
        """Provide sample manifests for the interactive workbench."""
        samples = {}
        for name, rel_path in [
            ("enterprise_sample", "k8s/enterprise-sample.yaml"),
            ("hardened_sample", "k8s/deployment.yaml"),
            ("insecure_sample", "k8s/insecure-sample.yaml"),
        ]:
            p = ROOT_DIR / rel_path
            if p.exists():
                samples[name] = p.read_text(encoding="utf-8")
        self._send_json(samples)

    # -------------------------------------------------------------------------
    # Helper & Static File Methods
    # -------------------------------------------------------------------------

    def _serve_static(self, path: str):
        """Serve files from the web/ directory."""
        if path in {"", "/"}:
            path = "/index.html"

        safe_path = (WEB_DIR / path.lstrip("/")).resolve()
        if not str(safe_path).startswith(str(WEB_DIR.resolve())) or not safe_path.exists():
            self._send_error(HTTPStatus.NOT_FOUND, "Static file not found")
            return

        content_type, _ = mimetypes.guess_type(str(safe_path))
        content_type = content_type or "application/octet-stream"

        try:
            data = safe_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _read_json_body(self) -> dict[str, Any]:
        """Read and parse JSON request body."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            data = self.rfile.read(length)
            return json.loads(data.decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK):
        """Send a JSON HTTP response."""
        encoded = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error(self, status: HTTPStatus, message: str):
        """Send a structured JSON error response."""
        self._send_json({"error": message, "status_code": status.value}, status=status)

    def _send_cors_headers(self):
        """Add CORS headers for browser interaction."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format, *args):
        """Suppress noisy default request logging or format cleanly."""
        pass


def run_server(host: str = "127.0.0.1", port: int = 8088):
    """Start the SecureGate API & Dashboard server with automatic port fallback."""
    current_port = port
    max_attempts = 10
    httpd = None

    for attempt in range(max_attempts):
        try:
            server_address = (host, current_port)
            httpd = ThreadingHTTPServer(server_address, SecureGateHandler)
            break
        except (PermissionError, OSError) as exc:
            if attempt == 0:
                print(
                    f"Notice: Port {current_port} is already in use or restricted "
                    f"(commonly used by Jenkins or Java services)."
                )
            current_port += 1
            if attempt == max_attempts - 1:
                raise RuntimeError(
                    f"Could not bind to any port in range {port}-{current_port}: {exc}"
                )

    print()
    print("=" * 60)
    print("          SECUREGATE WEB DASHBOARD & REST API")
    print("=" * 60)
    print(f"  URL             : http://{host}:{current_port}/")
    print(f"  API Healthcheck : http://{host}:{current_port}/api/status")
    print("  Press Ctrl+C to stop.")
    print("=" * 60, flush=True)
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down SecureGate server.")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
