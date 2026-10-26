import json

from securegate.models import Finding
from securegate.parser import TrivyParser


def test_trivy_parser_converts_vulnerabilities_to_findings(tmp_path):
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.19",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-40200",
                                "PkgName": "musl",
                                "InstalledVersion": "1.2.4-r0",
                                "FixedVersion": "1.2.4-r6",
                                "Severity": "high",
                                "Title": "musl vulnerability",
                                "PrimaryURL": "https://example.test/cve",
                                "Status": "fixed",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    scan_results = TrivyParser(str(report)).parse()

    assert len(scan_results) == 1
    assert scan_results[0].target == "alpine:3.19"

    finding = scan_results[0].findings[0]

    assert isinstance(finding, Finding)
    assert finding.id == "CVE-2026-40200"
    assert finding.source == "trivy"
    assert finding.category == "vulnerability"
    assert finding.severity == "HIGH"
    assert finding.resource == "musl"
    assert finding.message == "musl vulnerability"
    assert finding.evidence["target"] == "alpine:3.19"
    assert finding.metadata["installed_version"] == "1.2.4-r0"
    assert finding.metadata["fixed_version"] == "1.2.4-r6"

    assert finding.vulnerability_id == "CVE-2026-40200"
    assert finding.package == "musl"
    assert finding.installed_version == "1.2.4-r0"
    assert finding.fixed_version == "1.2.4-r6"
    assert finding.target == "alpine:3.19"
    assert scan_results[0].vulnerabilities == scan_results[0].findings
