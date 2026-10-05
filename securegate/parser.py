import json
from pathlib import Path

from .models import Vulnerability, ScanResult


class TrivyParser:
    def __init__(self, report_path: str):
        self.report_path = Path(report_path)

    def parse(self) -> list[ScanResult]:
        if not self.report_path.exists():
            raise FileNotFoundError(
                f"Trivy report not found: {self.report_path}"
            )

        if not self.report_path.is_file():
            raise ValueError(
                f"Trivy report is not a file: {self.report_path}"
            )

        try:
            with self.report_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON in Trivy report: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ValueError("Trivy report root must be a JSON object")

        results = data.get("Results", [])

        if results is None:
            results = []

        if not isinstance(results, list):
            raise ValueError("'Results' must be a list")

        scan_results = []

        for result in results:
            if not isinstance(result, dict):
                continue

            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities") or []

            if not isinstance(vulnerabilities, list):
                continue

            parsed_vulnerabilities = []

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue

                severity = str(
                    vuln.get("Severity", "UNKNOWN")
                ).upper()

                parsed_vulnerabilities.append(
                    Vulnerability(
                        vulnerability_id=str(
                            vuln.get("VulnerabilityID", "UNKNOWN")
                        ),
                        package=str(
                            vuln.get("PkgName", "UNKNOWN")
                        ),
                        installed_version=str(
                            vuln.get("InstalledVersion", "UNKNOWN")
                        ),
                        fixed_version=vuln.get("FixedVersion"),
                        severity=severity,
                        target=str(target),
                        title=vuln.get("Title")
                    )
                )

            scan_results.append(
                ScanResult(
                    target=str(target),
                    vulnerabilities=parsed_vulnerabilities
                )
            )

        return scan_results