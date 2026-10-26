"""Deployment-specific analyzer for Kubernetes inspection findings."""

from collections import Counter

from ..models import Finding, ScanResult


VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN",
}

DEPLOYMENT_CATEGORIES = {
    "privilege",
    "secret_exposure",
    "network_exposure",
    "resource_controls",
    "deployment_config",
}


class DeploymentAnalyzer:
    """Analyzes deployment security findings from Kubernetes inspection."""

    def __init__(self, scan_results: list[ScanResult]):
        self.scan_results = scan_results

    def findings(self):
        """Yield all deployment-related findings."""
        for result in self.scan_results:
            for finding in result.findings:
                if finding.category in DEPLOYMENT_CATEGORIES:
                    yield finding

    def all_findings(self):
        """Return all deployment findings as a list."""
        return list(self.findings())

    def severity_counts(self):
        """Return counts of findings by severity level."""
        counts = Counter()

        for finding in self.findings():
            severity = finding.severity

            if severity not in VALID_SEVERITIES:
                severity = "UNKNOWN"

            counts[severity] += 1

        return {
            severity: counts.get(severity, 0)
            for severity in [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN",
            ]
        }

    def total(self):
        """Return total number of deployment findings."""
        return sum(
            self.severity_counts().values()
        )

    def category_counts(self):
        """Return counts of findings by category."""
        counts = Counter()

        for finding in self.findings():
            counts[finding.category] += 1

        return dict(counts)

    def targets(self):
        """Return resource names from scan results."""
        return [
            result.target
            for result in self.scan_results
        ]
