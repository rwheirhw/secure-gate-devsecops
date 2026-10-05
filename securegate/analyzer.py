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

    def vulnerabilities(self):
        for result in self.scan_results:
            yield from result.vulnerabilities

    def all_vulnerabilities(self):
        return list(self.vulnerabilities())

    def severity_counts(self):
        counts = Counter()

        for vulnerability in self.vulnerabilities():
            severity = vulnerability.severity

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
            for vulnerability in self.vulnerabilities()
            if vulnerability.fixed_version
        )

    def targets(self):
        return [
            result.target
            for result in self.scan_results
        ]