"""Integration tests for SecureGate end-to-end workflows."""

import json
from textwrap import dedent

from typer.testing import CliRunner

from securegate.cli import app


runner = CliRunner()


def write_report(tmp_path, vulns):
    """Write a Trivy report with the given vulnerabilities list."""
    report_path = tmp_path / "trivy.json"
    report_path.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.19",
                        "Vulnerabilities": vulns,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return report_path


def write_manifest(tmp_path, content, filename="manifest.yaml"):
    path = tmp_path / filename
    path.write_text(
        dedent(content),
        encoding="utf-8",
    )
    return path


def write_policy(tmp_path, policy):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )
    return path


class TestAssessCommand:
    """Tests for the combined assess command."""

    def test_assess_blocks_on_high_vulnerability_and_insecure_manifest(
        self,
        tmp_path,
    ):
        report = write_report(
            tmp_path,
            [
                {
                    "VulnerabilityID": "CVE-2026-99999",
                    "PkgName": "curl",
                    "InstalledVersion": "8.0.0",
                    "FixedVersion": "8.1.0",
                    "Severity": "HIGH",
                    "Title": "curl overflow",
                }
            ],
        )
        manifest = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: app
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: nginx:latest
                      securityContext:
                        privileged: true
            """,
        )
        policy = write_policy(
            tmp_path,
            {
                "severity_policy": {
                    "HIGH": "BLOCK",
                    "MEDIUM": "WARN",
                },
                "finding_policy": {
                    "K8S_PRIVILEGED_CONTAINER": "BLOCK",
                },
                "max_allowed": {"HIGH": 0},
            },
        )

        result = runner.invoke(
            app,
            [
                "assess",
                str(report),
                str(manifest),
                "--policy",
                str(policy),
            ],
        )

        assert result.exit_code == 1
        assert "SECURITY DECISION: BLOCK" in result.output
        assert "CVE-2026-99999" in result.output
        assert "K8S_PRIVILEGED_CONTAINER" in result.output

    def test_assess_passes_clean_report_with_secure_manifest(
        self,
        tmp_path,
    ):
        report = write_report(
            tmp_path,
            [
                {
                    "VulnerabilityID": "CVE-2026-00001",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.3.2-r0",
                    "Severity": "LOW",
                    "Title": "minor issue",
                }
            ],
        )
        manifest = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: secure-app
            spec:
              template:
                spec:
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 1000
                  containers:
                    - name: app
                      image: example.com/app@sha256:1234567890abcdef
                      securityContext:
                        privileged: false
                        allowPrivilegeEscalation: false
                      resources:
                        requests:
                          cpu: 100m
                          memory: 128Mi
                        limits:
                          cpu: 500m
                          memory: 256Mi
            """,
        )
        policy = write_policy(
            tmp_path,
            {
                "severity_policy": {
                    "HIGH": "BLOCK",
                    "MEDIUM": "WARN",
                    "LOW": "ALLOW",
                },
            },
        )

        result = runner.invoke(
            app,
            [
                "assess",
                str(report),
                str(manifest),
                "--policy",
                str(policy),
            ],
        )

        assert result.exit_code == 0
        assert "SECURITY DECISION: PASS" in result.output

    def test_assess_writes_json_report(self, tmp_path):
        report = write_report(
            tmp_path,
            [
                {
                    "VulnerabilityID": "CVE-2026-00001",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.3.2-r0",
                    "Severity": "MEDIUM",
                    "Title": "issue",
                }
            ],
        )
        manifest = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: app
            spec:
              template:
                spec:
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 1000
                  containers:
                    - name: app
                      image: example.com/app@sha256:abcdef123456
                      securityContext:
                        privileged: false
                        allowPrivilegeEscalation: false
                      resources:
                        requests:
                          cpu: 100m
                          memory: 128Mi
                        limits:
                          cpu: 500m
                          memory: 256Mi
            """,
        )
        policy = write_policy(
            tmp_path,
            {
                "severity_policy": {
                    "HIGH": "BLOCK",
                    "MEDIUM": "WARN",
                    "LOW": "ALLOW",
                },
            },
        )

        json_output = tmp_path / "report.json"
        result = runner.invoke(
            app,
            [
                "assess",
                str(report),
                str(manifest),
                "--policy",
                str(policy),
                "--json-output",
                str(json_output),
            ],
        )

        assert result.exit_code == 0
        assert json_output.exists()
        assert "JSON report written" in result.output

        data = json.loads(
            json_output.read_text(encoding="utf-8")
        )

        assert data["decision"] == "PASS"
        assert data["metadata"]["mode"] == "combined"
        assert "risk" in data
        assert "summary" in data
        assert data["summary"]["total_findings"] > 0


class TestEvaluateJsonOutput:
    """Tests for JSON output on the evaluate command."""

    def test_evaluate_writes_json_report(self, tmp_path):
        report = write_report(
            tmp_path,
            [
                {
                    "VulnerabilityID": "CVE-2026-00001",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.3.2-r0",
                    "Severity": "MEDIUM",
                    "Title": "issue",
                }
            ],
        )
        policy = write_policy(
            tmp_path,
            {
                "severity_policy": {
                    "MEDIUM": "WARN",
                },
            },
        )

        json_output = tmp_path / "eval-report.json"
        result = runner.invoke(
            app,
            [
                "evaluate",
                str(report),
                "--policy",
                str(policy),
                "--json-output",
                str(json_output),
            ],
        )

        assert result.exit_code == 0
        assert json_output.exists()

        data = json.loads(
            json_output.read_text(encoding="utf-8")
        )

        assert data["decision"] == "PASS"
        assert "securegate_version" in data
        assert "timestamp" in data


class TestInspectJsonOutput:
    """Tests for JSON output on the inspect command."""

    def test_inspect_writes_json_report(self, tmp_path):
        manifest = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: app
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: nginx:latest
                      securityContext:
                        privileged: true
            """,
        )
        policy = write_policy(
            tmp_path,
            {
                "severity_policy": {
                    "CRITICAL": "BLOCK",
                },
                "finding_policy": {
                    "K8S_PRIVILEGED_CONTAINER": "BLOCK",
                },
            },
        )

        json_output = tmp_path / "inspect-report.json"
        result = runner.invoke(
            app,
            [
                "inspect",
                str(manifest),
                "--policy",
                str(policy),
                "--json-output",
                str(json_output),
            ],
        )

        assert result.exit_code == 1
        assert json_output.exists()

        data = json.loads(
            json_output.read_text(encoding="utf-8")
        )

        assert data["decision"] == "BLOCK"
        assert len(data["blocking_findings"]) > 0


class TestEndToEndDriftWorkflow:
    """Full workflow: baseline → modify → drift detect."""

    def test_full_baseline_to_drift_lifecycle(self, tmp_path):
        secure = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: lifecycle-app
            spec:
              template:
                spec:
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 1000
                  containers:
                    - name: app
                      image: example.com/app@sha256:abc123def456
                      securityContext:
                        privileged: false
                        allowPrivilegeEscalation: false
                      resources:
                        requests:
                          cpu: 100m
                          memory: 128Mi
                        limits:
                          cpu: 500m
                          memory: 256Mi
            """,
            filename="secure.yaml",
        )
        policy = write_policy(
            tmp_path,
            {
                "severity_policy": {
                    "CRITICAL": "BLOCK",
                    "HIGH": "BLOCK",
                    "MEDIUM": "WARN",
                },
                "finding_policy": {
                    "K8S_PRIVILEGED_CONTAINER": "BLOCK",
                },
            },
        )

        # Step 1: Create a baseline
        baseline_path = tmp_path / "baseline.json"
        result = runner.invoke(
            app,
            [
                "baseline",
                str(secure),
                "--policy",
                str(policy),
                "--output",
                str(baseline_path),
            ],
        )

        assert result.exit_code == 0
        assert baseline_path.exists()

        # Step 2: Create a drifted manifest
        drifted = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: lifecycle-app
            spec:
              template:
                spec:
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 1000
                  containers:
                    - name: app
                      image: example.com/app:latest
                      securityContext:
                        privileged: true
                        allowPrivilegeEscalation: false
                      resources:
                        requests:
                          cpu: 100m
                          memory: 128Mi
                        limits:
                          cpu: 500m
                          memory: 256Mi
            """,
            filename="drifted.yaml",
        )

        # Step 3: Detect drift
        drift_result = runner.invoke(
            app,
            [
                "drift",
                str(baseline_path),
                str(drifted),
                "--policy",
                str(policy),
            ],
        )

        assert drift_result.exit_code == 1
        assert "SECURITY DECISION: BLOCK" in drift_result.output
        assert "DRIFT" in drift_result.output


class TestVersionCommand:
    """Tests for the version command."""

    def test_version_displays_current_version(self):
        result = runner.invoke(
            app,
            ["version"],
        )

        assert result.exit_code == 0
        assert "SecureGate 0.2.0" in result.output


class TestErrorHandling:
    """Tests for error handling edge cases."""

    def test_evaluate_returns_error_code_for_missing_report(self, tmp_path):
        policy = write_policy(
            tmp_path,
            {"severity_policy": {}},
        )

        result = runner.invoke(
            app,
            [
                "evaluate",
                str(tmp_path / "nonexistent.json"),
                "--policy",
                str(policy),
            ],
        )

        assert result.exit_code == 2

    def test_inspect_returns_error_code_for_missing_manifest(self, tmp_path):
        policy = write_policy(
            tmp_path,
            {"severity_policy": {}},
        )

        result = runner.invoke(
            app,
            [
                "inspect",
                str(tmp_path / "nonexistent.yaml"),
                "--policy",
                str(policy),
            ],
        )

        assert result.exit_code == 2

    def test_assess_returns_error_code_for_missing_report(self, tmp_path):
        manifest = write_manifest(
            tmp_path,
            """\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: app
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: nginx:latest
            """,
        )
        policy = write_policy(
            tmp_path,
            {"severity_policy": {}},
        )

        result = runner.invoke(
            app,
            [
                "assess",
                str(tmp_path / "nonexistent.json"),
                str(manifest),
                "--policy",
                str(policy),
            ],
        )

        assert result.exit_code == 2

    def test_evaluate_empty_results_passes(self, tmp_path):
        report = tmp_path / "empty.json"
        report.write_text(
            json.dumps({"Results": []}),
            encoding="utf-8",
        )
        policy = write_policy(
            tmp_path,
            {"severity_policy": {}},
        )

        result = runner.invoke(
            app,
            [
                "evaluate",
                str(report),
                "--policy",
                str(policy),
            ],
        )

        assert result.exit_code == 0
        assert "SECURITY DECISION: PASS" in result.output
