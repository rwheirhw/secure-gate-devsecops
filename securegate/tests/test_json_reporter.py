"""Unit tests for JsonReporter."""

import json
from pathlib import Path

from securegate import __version__
from securegate.analyzer import Analyzer
from securegate.json_reporter import JsonReporter
from securegate.models import Finding, PolicyDecision, RiskAssessment, ScanResult


def test_json_reporter_generates_complete_dict(tmp_path):
    vuln = Finding(
        id="CVE-2024-1111",
        source="trivy",
        category="vulnerability",
        severity="HIGH",
        resource="openssl",
        message="Vulnerability in openssl",
        evidence={"cve": "CVE-2024-1111"},
        metadata={
            "package": "openssl",
            "installed_version": "1.1.1",
            "fixed_version": "1.1.2",
            "target": "my-app:latest",
        },
    )
    k8s = Finding(
        id="K8S_PRIVILEGED_CONTAINER",
        source="kubernetes",
        category="privilege",
        severity="CRITICAL",
        resource="Deployment/default/app",
        message="Container is privileged",
        evidence={"privileged": True},
    )
    ignored = Finding(
        id="LOW_01",
        source="trivy",
        category="vulnerability",
        severity="LOW",
        resource="zlib",
        message="Low issue",
    )

    analyzer = Analyzer([ScanResult(target="my-app:latest", findings=[vuln, k8s, ignored])])
    decision = PolicyDecision(
        decision="BLOCK",
        blocking=[vuln, k8s],
        warnings=[],
        ignored=[ignored],
        counts={"BLOCK": 2, "WARN": 0, "ALLOW": 1},
    )
    risk = RiskAssessment(
        artifact_risk=15,
        deployment_risk=32,
        drift_risk=0,
        total_risk=47,
        level="MEDIUM",
    )

    report = JsonReporter.generate(
        decision=decision,
        analyzer=analyzer,
        risk=risk,
        metadata={"build_id": "42"},
    )

    assert report["securegate_version"] == __version__
    assert "timestamp" in report
    assert report["decision"] == "BLOCK"
    assert report["metadata"] == {"build_id": "42"}
    assert report["targets"] == ["my-app:latest"]

    summary = report["summary"]
    assert summary["total_findings"] == 3
    assert summary["blocking"] == 2
    assert summary["warnings"] == 0
    assert summary["ignored"] == 1
    assert summary["fixable"] == 1

    assert report["risk"] == {
        "artifact_risk": 15,
        "deployment_risk": 32,
        "drift_risk": 0,
        "total_risk": 47,
        "level": "MEDIUM",
    }

    assert len(report["blocking_findings"]) == 2
    vuln_dict = report["blocking_findings"][0]
    assert vuln_dict["id"] == "CVE-2024-1111"
    assert vuln_dict["package"] == "openssl"
    assert vuln_dict["installed_version"] == "1.1.1"
    assert vuln_dict["fixed_version"] == "1.1.2"
    assert vuln_dict["evidence"] == {"cve": "CVE-2024-1111"}

    assert len(report["ignored_findings"]) == 1
    assert report["ignored_findings"][0]["id"] == "LOW_01"


def test_json_reporter_write_creates_file_and_subdirs(tmp_path):
    output_path = tmp_path / "deep" / "nested" / "report.json"
    data = {"test_key": "test_value"}

    written_path = JsonReporter.write(data, str(output_path))

    assert written_path == output_path
    assert output_path.exists()
    content = json.loads(output_path.read_text(encoding="utf-8"))
    assert content == data
