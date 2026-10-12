import json

from securegate.baseline import BaselineStore, DriftDetector
from securegate.models import RiskAssessment


def posture(image="example.com/app@sha256:abc", privileged=False):
    return {
        "resources": [
            {
                "resource": "Deployment/app",
                "kind": "Deployment",
                "name": "app",
                "namespace": None,
                "pod": {
                    "hostNetwork": False,
                    "hostPID": False,
                    "hostIPC": False,
                    "containers": {
                        "app": {
                            "name": "app",
                            "image": image,
                            "securityContext": {
                                "privileged": privileged,
                            },
                            "resources": {},
                            "secretReferences": [],
                            "plaintextSecretEnv": [],
                        }
                    },
                },
            }
        ]
    }


def test_baseline_store_writes_and_loads_security_posture(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    risk = RiskAssessment(
        artifact_risk=0,
        deployment_risk=0,
        drift_risk=0,
        total_risk=0,
        level="LOW",
    )

    BaselineStore().save(
        output_path=str(baseline_path),
        manifest="deployment.yaml",
        posture=posture(),
        risk=risk,
    )

    data = json.loads(
        baseline_path.read_text(encoding="utf-8")
    )

    assert data["manifest"] == "deployment.yaml"
    assert data["risk"]["total_risk"] == 0
    assert data["posture"]["resources"][0]["resource"] == "Deployment/app"
    assert BaselineStore().load(str(baseline_path)) == data


def test_drift_detector_reports_security_posture_changes_as_findings():
    detector = DriftDetector()
    events = detector.detect(
        posture(),
        posture(
            image="example.com/app:latest",
            privileged=True,
        ),
    )
    findings = detector.findings_for(events)

    assert {
        event.field
        for event in events
    } == {
        "pod.containers.app.image",
        "pod.containers.app.securityContext.privileged",
    }
    assert {
        finding.source
        for finding in findings
    } == {"drift"}
    assert {
        finding.category
        for finding in findings
    } == {"drift"}
    assert {
        finding.severity
        for finding in findings
    } == {"HIGH", "CRITICAL"}
