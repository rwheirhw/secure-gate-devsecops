import json
from textwrap import dedent

from typer.testing import CliRunner

from securegate.cli import app


def write_report(tmp_path, severity):
    report_path = tmp_path / "trivy.json"
    report_path.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:latest",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": f"CVE-{severity}",
                                "PkgName": "zlib",
                                "InstalledVersion": "1.3.2-r0",
                                "FixedVersion": "1.3.2-r1",
                                "Severity": severity,
                                "Title": "zlib vulnerability",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return report_path


def write_manifest(tmp_path):
    manifest_path = tmp_path / "deployment.yaml"
    manifest_path.write_text(
        dedent(
            """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: insecure-app
            spec:
              template:
                spec:
                  containers:
                    - name: app
                      image: nginx:latest
                      securityContext:
                        privileged: true
            """
        ),
        encoding="utf-8",
    )
    return manifest_path


def write_secure_manifest(tmp_path):
    manifest_path = tmp_path / "secure-deployment.yaml"
    manifest_path.write_text(
        dedent(
            """
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
            """
        ),
        encoding="utf-8",
    )
    return manifest_path


def write_drifted_manifest(tmp_path):
    manifest_path = tmp_path / "drifted-deployment.yaml"
    manifest_path.write_text(
        dedent(
            """
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
            """
        ),
        encoding="utf-8",
    )
    return manifest_path


def write_policy(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "severity_policy": {
                    "CRITICAL": "BLOCK",
                    "HIGH": "BLOCK",
                    "MEDIUM": "WARN",
                    "LOW": "ALLOW",
                },
                "finding_policy": {
                    "K8S_PRIVILEGED_CONTAINER": "BLOCK",
                },
                "max_allowed": {
                    "HIGH": 0,
                },
            }
        ),
        encoding="utf-8",
    )
    return policy_path


def test_evaluate_returns_block_exit_code_for_blocking_findings(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "evaluate",
            str(write_report(tmp_path, "HIGH")),
            "--policy",
            str(write_policy(tmp_path)),
        ],
    )

    assert result.exit_code == 1
    assert "SECURITY DECISION: BLOCK" in result.output
    assert "CVE-HIGH" in result.output


def test_evaluate_returns_success_exit_code_for_warning_only_findings(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "evaluate",
            str(write_report(tmp_path, "MEDIUM")),
            "--policy",
            str(write_policy(tmp_path)),
        ],
    )

    assert result.exit_code == 0
    assert "SECURITY DECISION: PASS" in result.output
    assert "CVE-MEDIUM" in result.output


def test_inspect_returns_block_exit_code_for_insecure_manifest(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "inspect",
            str(write_manifest(tmp_path)),
            "--policy",
            str(write_policy(tmp_path)),
        ],
    )

    assert result.exit_code == 1
    assert "SECURITY DECISION: BLOCK" in result.output
    assert "K8S_PRIVILEGED_CONTAINER" in result.output


def test_baseline_writes_approved_security_posture(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "baseline",
            str(write_secure_manifest(tmp_path)),
            "--policy",
            str(write_policy(tmp_path)),
            "--output",
            str(baseline_path),
        ],
    )

    assert result.exit_code == 0
    assert baseline_path.exists()
    assert "Approved security baseline written" in result.output


def test_drift_returns_block_exit_code_for_security_posture_drift(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    runner = CliRunner()

    baseline_result = runner.invoke(
        app,
        [
            "baseline",
            str(write_secure_manifest(tmp_path)),
            "--policy",
            str(write_policy(tmp_path)),
            "--output",
            str(baseline_path),
        ],
    )

    assert baseline_result.exit_code == 0

    drift_result = runner.invoke(
        app,
        [
            "drift",
            str(baseline_path),
            str(write_drifted_manifest(tmp_path)),
            "--policy",
            str(write_policy(tmp_path)),
        ],
    )

    assert drift_result.exit_code == 1
    assert "SECURITY DECISION: BLOCK" in drift_result.output
    assert "DRIFT_POD_CONTAINERS_APP_SECURITYCONTEXT_PRIVILEGED" in drift_result.output
