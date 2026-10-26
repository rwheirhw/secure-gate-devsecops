"""Structured JSON report output for SecureGate assessments.

Produces machine-readable JSON reports that can be consumed by CI/CD
pipelines, dashboards, and downstream tooling.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .models import PolicyDecision, RiskAssessment


class JsonReporter:
    """Generates structured JSON assessment reports."""

    @staticmethod
    def generate(
        decision: PolicyDecision,
        analyzer,
        risk: RiskAssessment | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a structured report dictionary."""
        all_findings = analyzer.all_findings()

        report = {
            "securegate_version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": decision.decision,
            "summary": {
                "total_findings": len(all_findings),
                "blocking": len(decision.blocking),
                "warnings": len(decision.warnings),
                "ignored": len(decision.ignored),
                "severity_counts": analyzer.severity_counts(),
                "fixable": analyzer.fixable_count(),
            },
            "targets": analyzer.targets(),
        }

        if metadata:
            report["metadata"] = metadata

        if risk:
            report["risk"] = asdict(risk)

        report["blocking_findings"] = [
            JsonReporter._finding_to_dict(finding)
            for finding in decision.blocking
        ]

        report["warning_findings"] = [
            JsonReporter._finding_to_dict(finding)
            for finding in decision.warnings
        ]

        report["ignored_findings"] = [
            {
                "id": finding.id,
                "severity": finding.severity,
                "category": finding.category,
            }
            for finding in decision.ignored
        ]

        return report

    @staticmethod
    def write(
        report: dict[str, Any],
        output_path: str,
    ) -> Path:
        """Write a report dictionary to a JSON file."""
        path = Path(output_path)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with path.open("w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=2,
                sort_keys=False,
            )
            file.write("\n")

        return path

    @staticmethod
    def _finding_to_dict(finding) -> dict[str, Any]:
        """Convert a Finding to a serializable dictionary."""
        result = {
            "id": finding.id,
            "source": finding.source,
            "category": finding.category,
            "severity": finding.severity,
            "resource": finding.resource,
            "message": finding.message,
        }

        if finding.evidence:
            result["evidence"] = finding.evidence

        if finding.category == "vulnerability":
            result["package"] = finding.package
            result["installed_version"] = finding.installed_version
            result["fixed_version"] = (
                finding.fixed_version
                or None
            )

        return result
