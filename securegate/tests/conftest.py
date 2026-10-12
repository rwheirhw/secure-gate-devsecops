"""Shared test fixtures for SecureGate tests."""

import json
from textwrap import dedent

import pytest

from securegate.models import Finding, ScanResult


@pytest.fixture
def make_finding():
    """Factory fixture for creating Finding instances."""

    def _make(
        finding_id="CVE-2026-00001",
        source="trivy",
        category="vulnerability",
        severity="HIGH",
        resource="openssl",
        message=None,
        evidence=None,
        metadata=None,
    ):
        return Finding(
            id=finding_id,
            source=source,
            category=category,
            severity=severity,
            resource=resource,
            message=message or finding_id,
            evidence=evidence or {},
            metadata=metadata or {
                "package": resource,
                "installed_version": "1.0.0",
                "fixed_version": "1.0.1",
                "target": "alpine:latest",
            },
        )

    return _make


@pytest.fixture
def make_k8s_finding():
    """Factory fixture for creating Kubernetes findings."""

    def _make(
        rule_id="K8S_PRIVILEGED_CONTAINER",
        category="privilege",
        severity="CRITICAL",
        resource="Deployment/app",
        message=None,
    ):
        return Finding(
            id=rule_id,
            source="kubernetes",
            category=category,
            severity=severity,
            resource=resource,
            message=message or rule_id,
            evidence={"container": "app"},
            metadata={"rule": rule_id},
        )

    return _make


@pytest.fixture
def trivy_report_path(tmp_path):
    """Write a standard Trivy JSON report and return its path."""
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
                                "Severity": "HIGH",
                                "Title": "musl buffer overflow",
                            },
                            {
                                "VulnerabilityID": "CVE-2026-40201",
                                "PkgName": "zlib",
                                "InstalledVersion": "1.3.2-r0",
                                "Severity": "MEDIUM",
                                "Title": "zlib deflate issue",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return report


@pytest.fixture
def insecure_manifest_path(tmp_path):
    """Write an insecure K8s manifest and return its path."""
    path = tmp_path / "insecure.yaml"
    path.write_text(
        dedent(
            """\
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
    return path


@pytest.fixture
def secure_manifest_path(tmp_path):
    """Write a secure K8s manifest and return its path."""
    path = tmp_path / "secure.yaml"
    path.write_text(
        dedent(
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
            """
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def policy_path(tmp_path):
    """Write a standard policy and return its path."""
    path = tmp_path / "policy.json"
    path.write_text(
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
    return path
