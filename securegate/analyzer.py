from collections import Counter

from .models import ScanResult


VALID_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN"
}


class Analyzer:

    def __init__(self, scan_results: list[ScanResult]):
        self.scan_results = scan_results

    def findings(self):
        for result in self.scan_results:
            yield from result.findings

    def all_findings(self):
        return list(self.findings())

    def vulnerabilities(self):
        return self.findings()

    def all_vulnerabilities(self):
        return self.all_findings()

    def severity_counts(self):
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
                "UNKNOWN"
            ]
        }

    def total(self):
        return sum(
            self.severity_counts().values()
        )

    def fixable_count(self):
        return sum(
            1
            for finding in self.findings()
            if finding.fixed_version
        )

    def targets(self):
        return [
            result.target
            for result in self.scan_results
        ]
