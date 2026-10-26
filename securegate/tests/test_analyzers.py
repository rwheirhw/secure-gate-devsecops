"""Unit tests for VulnerabilityAnalyzer and DeploymentAnalyzer packages."""

from securegate.analyzers.deployment import DeploymentAnalyzer
from securegate.analyzers.vulnerability import VulnerabilityAnalyzer
from securegate.models import Finding, ScanResult


def make_vuln(finding_id: str, severity: str, fixed_version: str | None = None) -> Finding:
    return Finding(
        id=finding_id,
        source="trivy",
        category="vulnerability",
        severity=severity,
        resource="curl",
        message=f"Vulnerability {finding_id}",
        metadata={
            "package": "curl",
            "fixed_version": fixed_version,
            "target": "app:1.0",
        },
    )


def make_deployment(
    finding_id: str,
    category: str,
    severity: str,
    resource: str = "Deployment/default/app",
) -> Finding:
    return Finding(
        id=finding_id,
        source="kubernetes",
        category=category,
        severity=severity,
        resource=resource,
        message=f"Deployment issue {finding_id}",
    )


class TestVulnerabilityAnalyzer:
    def test_filters_only_vulnerability_category(self):
        vuln = make_vuln("CVE-2024-0001", "HIGH", "7.8.0")
        k8s_priv = make_deployment("K8S_PRIVILEGED_CONTAINER", "privilege", "CRITICAL")
        drift = Finding(
            id="DRIFT_PRIVILEGED",
            source="drift",
            category="drift",
            severity="CRITICAL",
            resource="Deployment/default/app",
            message="Drift detected",
        )

        scan_result = ScanResult(
            target="app:1.0",
            findings=[vuln, k8s_priv, drift],
        )
        analyzer = VulnerabilityAnalyzer([scan_result])

        assert analyzer.all_findings() == [vuln]
        assert analyzer.total() == 1
        assert analyzer.fixable_count() == 1
        assert analyzer.targets() == ["app:1.0"]

    def test_severity_counts_and_unknown_handling(self):
        findings = [
            make_vuln("CVE-1", "CRITICAL", "1.0"),
            make_vuln("CVE-2", "HIGH"),
            make_vuln("CVE-3", "MEDIUM"),
            make_vuln("CVE-4", "LOW"),
            make_vuln("CVE-5", "WEIRD_SEVERITY"),
        ]
        analyzer = VulnerabilityAnalyzer([ScanResult(target="app:1.0", findings=findings)])

        counts = analyzer.severity_counts()
        assert counts == {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 1,
            "LOW": 1,
            "UNKNOWN": 1,
        }
        assert analyzer.total() == 5
        assert analyzer.fixable_count() == 1


class TestDeploymentAnalyzer:
    def test_filters_deployment_categories_only(self):
        priv = make_deployment("K8S_PRIVILEGED", "privilege", "CRITICAL")
        secret = make_deployment("K8S_SECRET", "secret_exposure", "HIGH")
        net = make_deployment("K8S_NET", "network_exposure", "MEDIUM")
        res = make_deployment("K8S_RES", "resource_controls", "LOW")
        cfg = make_deployment("K8S_CFG", "deployment_config", "LOW")
        vuln = make_vuln("CVE-1", "HIGH")
        drift = Finding(
            id="DRIFT_01",
            source="drift",
            category="drift",
            severity="HIGH",
            resource="app",
            message="drift",
        )

        scan_result = ScanResult(
            target="k8s/manifest.yaml",
            findings=[priv, secret, net, res, cfg, vuln, drift],
        )
        analyzer = DeploymentAnalyzer([scan_result])

        findings = analyzer.all_findings()
        assert len(findings) == 5
        assert priv in findings
        assert secret in findings
        assert net in findings
        assert res in findings
        assert cfg in findings
        assert vuln not in findings
        assert drift not in findings

    def test_category_counts_and_targets(self):
        priv = make_deployment("K8S_PRIV", "privilege", "CRITICAL")
        priv2 = make_deployment("K8S_ROOT", "privilege", "HIGH")
        secret = make_deployment("K8S_SECRET", "secret_exposure", "HIGH")

        analyzer = DeploymentAnalyzer(
            [ScanResult(target="k8s/app.yaml", findings=[priv, priv2, secret])]
        )

        assert analyzer.category_counts() == {
            "privilege": 2,
            "secret_exposure": 1,
        }
        assert analyzer.total() == 3
        assert analyzer.targets() == ["k8s/app.yaml"]
