"""Tests verifying public package exports and backward-compatibility shims."""

def test_policy_exports_and_compatibility():
    from securegate.policy import PolicyEngine as EngineFromShim
    from securegate.policy.engine import PolicyEngine as EngineFromPackage

    assert EngineFromShim is EngineFromPackage


def test_analyzers_exports():
    from securegate.analyzers import DeploymentAnalyzer, VulnerabilityAnalyzer
    from securegate.analyzers.deployment import DeploymentAnalyzer as DirectDep
    from securegate.analyzers.vulnerability import VulnerabilityAnalyzer as DirectVuln

    assert DeploymentAnalyzer is DirectDep
    assert VulnerabilityAnalyzer is DirectVuln


def test_scanners_and_inspectors_exports():
    from securegate.scanner import TrivyScanner as ScannerFromShim
    from securegate.scanners.trivy import TrivyScanner as ScannerFromPackage
    from securegate.inspectors.kubernetes import KubernetesInspector

    assert ScannerFromShim is ScannerFromPackage
    assert KubernetesInspector is not None
