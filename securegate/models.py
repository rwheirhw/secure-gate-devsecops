from dataclasses import dataclass
from typing import Optional


@dataclass
class Vulnerability:
    vulnerability_id: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    target: str
    title: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    vulnerabilities: list[Vulnerability]


@dataclass
class PolicyDecision:
    decision: str
    blocking: list[Vulnerability]
    warnings: list[Vulnerability]
    ignored: list[Vulnerability]
    counts: dict[str, int]