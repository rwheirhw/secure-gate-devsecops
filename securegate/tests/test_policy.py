import json

import pytest

from securegate.models import Finding
from securegate.policy import PolicyEngine


def make_finding(
    finding_id: str,
    severity: str,
    category: str = "vulnerability",
) -> Finding:
    return Finding(
        id=finding_id,
        source="trivy" if category == "vulnerability" else "kubernetes",
        category=category,
        severity=severity,
        resource="busybox",
        message=finding_id,
        metadata={
            "package": "busybox",
            "target": "alpine:latest",
        },
    )


def write_policy(tmp_path, policy):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(policy),
        encoding="utf-8",
    )
    return policy_path


def test_policy_engine_evaluates_vulnerability_findings_by_severity(tmp_path):
    policy_path = write_policy(
        tmp_path,
        {
            "severity_policy": {
                "HIGH": "BLOCK",
                "MEDIUM": "WARN",
                "LOW": "ALLOW",
            },
            "max_allowed": {
                "HIGH": 0,
            },
        },
    )

    high = make_finding("CVE-HIGH", "HIGH")
    medium = make_finding("CVE-MEDIUM", "MEDIUM")
    low = make_finding("CVE-LOW", "LOW")

    decision = PolicyEngine(str(policy_path)).evaluate(
        [high, medium, low]
    )

    assert decision.decision == "BLOCK"
    assert decision.blocking == [high]
    assert decision.warnings == [medium]
    assert decision.ignored == []
    assert decision.counts == {
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
    }


def test_policy_engine_evaluates_kubernetes_findings_by_rule_id(tmp_path):
    policy_path = write_policy(
        tmp_path,
        {
            "severity_policy": {
                "HIGH": "WARN",
            },
            "finding_policy": {
                "K8S_PRIVILEGED_CONTAINER": "BLOCK",
            },
        },
    )

    finding = make_finding(
        "K8S_PRIVILEGED_CONTAINER",
        "HIGH",
        "privilege",
    )

    decision = PolicyEngine(str(policy_path)).evaluate([finding])

    assert decision.decision == "BLOCK"
    assert decision.blocking == [finding]


def test_policy_engine_evaluates_kubernetes_findings_by_category(tmp_path):
    policy_path = write_policy(
        tmp_path,
        {
            "severity_policy": {
                "MEDIUM": "ALLOW",
            },
            "category_policy": {
                "resource_controls": "WARN",
            },
        },
    )

    finding = make_finding(
        "K8S_MISSING_RESOURCE_CONTROLS",
        "MEDIUM",
        "resource_controls",
    )

    decision = PolicyEngine(str(policy_path)).evaluate([finding])

    assert decision.decision == "PASS"
    assert decision.warnings == [finding]


def test_policy_engine_keeps_existing_ignored_vulnerability_policy(tmp_path):
    policy_path = write_policy(
        tmp_path,
        {
            "severity_policy": {
                "HIGH": "BLOCK",
            },
            "ignored_vulnerabilities": [
                "CVE-IGNORED",
            ],
            "max_allowed": {
                "HIGH": 0,
            },
        },
    )

    ignored = make_finding("CVE-IGNORED", "HIGH")

    decision = PolicyEngine(str(policy_path)).evaluate([ignored])

    assert decision.decision == "PASS"
    assert decision.blocking == []
    assert decision.warnings == []
    assert decision.ignored == [ignored]


def test_policy_engine_ignores_generic_findings(tmp_path):
    policy_path = write_policy(
        tmp_path,
        {
            "severity_policy": {
                "HIGH": "BLOCK",
            },
            "ignored_findings": [
                "K8S_HOST_NETWORK",
            ],
        },
    )

    ignored = make_finding(
        "K8S_HOST_NETWORK",
        "HIGH",
        "network_exposure",
    )

    decision = PolicyEngine(str(policy_path)).evaluate([ignored])

    assert decision.decision == "PASS"
    assert decision.ignored == [ignored]


def test_policy_engine_rejects_invalid_actions(tmp_path):
    policy_path = write_policy(
        tmp_path,
        {
            "severity_policy": {
                "HIGH": "DENY",
            },
        },
    )

    with pytest.raises(ValueError, match="Invalid policy action"):
        PolicyEngine(str(policy_path))


def test_policy_engine_loads_yaml_policy(tmp_path):
    yaml_content = """
    severity_policy:
      HIGH: BLOCK
      MEDIUM: WARN
      LOW: ALLOW
    finding_policy:
      K8S_PRIVILEGED_CONTAINER: BLOCK
    category_policy:
      privilege: BLOCK
    max_allowed:
      HIGH: 0
    """
    yaml_policy = tmp_path / "policy.yaml"
    yaml_policy.write_text(yaml_content, encoding="utf-8")

    engine = PolicyEngine(str(yaml_policy))
    high = make_finding("CVE-HIGH", "HIGH")
    decision = engine.evaluate([high])

    assert decision.decision == "BLOCK"
    assert len(decision.blocking) == 1
