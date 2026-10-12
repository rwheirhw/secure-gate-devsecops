from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Finding:
    id: str
    source: str
    category: str
    severity: str
    resource: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def vulnerability_id(self) -> str:
        return self.id

    @property
    def package(self) -> str:
        return str(
            self.metadata.get("package", self.resource)
        )

    @property
    def installed_version(self) -> str:
        return str(
            self.metadata.get("installed_version", "UNKNOWN")
        )

    @property
    def fixed_version(self) -> Optional[str]:
        return self.metadata.get("fixed_version")

    @property
    def target(self) -> str:
        return str(
            self.metadata.get("target", self.resource)
        )

    @property
    def title(self) -> Optional[str]:
        return self.metadata.get("title")


@dataclass
class ScanResult:
    target: str
    findings: list[Finding]

    @property
    def vulnerabilities(self) -> list[Finding]:
        return self.findings


@dataclass
class PolicyDecision:
    decision: str
    blocking: list[Finding]
    warnings: list[Finding]
    ignored: list[Finding]
    counts: dict[str, int]


@dataclass
class RiskAssessment:
    artifact_risk: int
    deployment_risk: int
    drift_risk: int
    total_risk: int
    level: str


@dataclass
class SecurityBaseline:
    manifest: str
    approved_at: str
    risk: RiskAssessment
    posture: dict[str, Any]


@dataclass
class DriftEvent:
    id: str
    resource: str
    field: str
    approved_value: Any
    current_value: Any
    severity: str
    message: str
