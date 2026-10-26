from .models import Finding, RiskAssessment


SEVERITY_POINTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 2,
    "UNKNOWN": 5,
}

CATEGORY_MULTIPLIERS = {
    "vulnerability": 1.0,
    "privilege": 1.3,
    "secret_exposure": 1.2,
    "network_exposure": 1.0,
    "resource_controls": 0.7,
    "deployment_config": 0.7,
    "drift": 1.5,
}


class RiskEngine:
    def assess(
        self,
        findings: list[Finding],
    ) -> RiskAssessment:
        artifact_score = 0
        deployment_score = 0
        drift_score = 0

        for finding in findings:
            points = self._finding_points(finding)

            if finding.category == "vulnerability":
                artifact_score += points
            elif finding.category == "drift":
                drift_score += points
            else:
                deployment_score += points

        artifact_risk = min(
            40,
            round(artifact_score),
        )
        deployment_risk = min(
            45,
            round(deployment_score),
        )
        drift_risk = min(
            30,
            round(drift_score),
        )
        total_risk = min(
            100,
            artifact_risk
            + deployment_risk
            + drift_risk,
        )

        return RiskAssessment(
            artifact_risk=artifact_risk,
            deployment_risk=deployment_risk,
            drift_risk=drift_risk,
            total_risk=total_risk,
            level=self._level(total_risk),
        )

    def _finding_points(self, finding: Finding) -> float:
        severity = finding.severity

        if severity not in SEVERITY_POINTS:
            severity = "UNKNOWN"

        return (
            SEVERITY_POINTS[severity]
            * CATEGORY_MULTIPLIERS.get(finding.category, 1.0)
        )

    def _level(
        self,
        total_risk: int,
    ) -> str:
        if total_risk >= 80:
            return "CRITICAL"

        if total_risk >= 60:
            return "HIGH"

        if total_risk >= 30:
            return "MEDIUM"

        return "LOW"
