from securegate.models import Finding
from securegate.risk import RiskEngine


def finding(
    finding_id,
    category,
    severity,
):
    return Finding(
        id=finding_id,
        source="test",
        category=category,
        severity=severity,
        resource="resource",
        message=finding_id,
    )


def test_risk_engine_scores_artifact_deployment_and_drift_risk():
    risk = RiskEngine().assess(
        [
            finding("CVE-1", "vulnerability", "HIGH"),
            finding("K8S_PRIVILEGED_CONTAINER", "privilege", "CRITICAL"),
            finding("DRIFT_IMAGE", "drift", "HIGH"),
        ]
    )

    assert risk.artifact_risk == 15
    assert risk.deployment_risk == 32
    assert risk.drift_risk == 22
    assert risk.total_risk == 69
    assert risk.level == "HIGH"
