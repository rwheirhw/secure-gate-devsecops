from securegate.analyzer import Analyzer
from securegate.models import Finding, ScanResult


def make_finding(
    finding_id: str,
    severity: str,
    fixed_version: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        source="trivy",
        category="vulnerability",
        severity=severity,
        resource="openssl",
        message=finding_id,
        metadata={
            "package": "openssl",
            "fixed_version": fixed_version,
            "target": "app:latest",
        },
    )


def test_analyzer_summarizes_generic_findings():
    findings = [
        make_finding("CVE-1", "HIGH", "3.0.0"),
        make_finding("CVE-2", "MEDIUM"),
        make_finding("CVE-3", "NOT_A_SEVERITY"),
    ]
    analyzer = Analyzer(
        [
            ScanResult(
                target="app:latest",
                findings=findings,
            )
        ]
    )

    assert analyzer.all_findings() == findings
    assert analyzer.all_vulnerabilities() == findings
    assert analyzer.severity_counts() == {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 0,
        "UNKNOWN": 1,
    }
    assert analyzer.total() == 3
    assert analyzer.fixable_count() == 1
    assert analyzer.targets() == ["app:latest"]
