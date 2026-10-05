import json
from pathlib import Path

from .models import PolicyDecision


VALID_ACTIONS = {
    "ALLOW",
    "WARN",
    "BLOCK"
}


class PolicyEngine:

    def __init__(self, policy_path: str):
        self.policy_path = Path(policy_path)
        self.policy = self._load_policy()

    def _load_policy(self):
        if not self.policy_path.exists():
            raise FileNotFoundError(
                f"Policy file not found: {self.policy_path}"
            )

        with self.policy_path.open(
            "r",
            encoding="utf-8"
        ) as file:
            policy = json.load(file)

        if not isinstance(policy, dict):
            raise ValueError("Policy must be a JSON object")

        severity_policy = policy.get(
            "severity_policy",
            {}
        )

        for severity, action in severity_policy.items():
            if action not in VALID_ACTIONS:
                raise ValueError(
                    f"Invalid policy action for {severity}: {action}"
                )

        return policy

    def evaluate(self, vulnerabilities):

        severity_policy = self.policy.get(
            "severity_policy",
            {}
        )

        ignored_ids = set(
            self.policy.get(
                "ignored_vulnerabilities",
                []
            )
        )

        blocking = []
        warnings = []
        ignored = []

        for vulnerability in vulnerabilities:

            if vulnerability.vulnerability_id in ignored_ids:
                ignored.append(vulnerability)
                continue

            action = severity_policy.get(
                vulnerability.severity,
                "WARN"
            )

            if action == "BLOCK":
                blocking.append(vulnerability)

            elif action == "WARN":
                warnings.append(vulnerability)

        counts = {}

        for vulnerability in vulnerabilities:
            severity = vulnerability.severity
            counts[severity] = counts.get(
                severity,
                0
            ) + 1

        # Apply explicit maximum-count rules.
        max_allowed = self.policy.get(
            "max_allowed",
            {}
        )

        for severity, maximum in max_allowed.items():

            effective_count = sum(
                1
                for vulnerability in vulnerabilities
                if (
                    vulnerability.severity == severity
                    and vulnerability.vulnerability_id
                    not in ignored_ids
                )
            )

            if effective_count > maximum:

                # Avoid duplicate entries.
                for vulnerability in vulnerabilities:
                    if (
                        vulnerability.severity == severity
                        and vulnerability.vulnerability_id
                        not in ignored_ids
                        and vulnerability
                        not in blocking
                    ):
                        blocking.append(vulnerability)

        decision = "BLOCK" if blocking else "PASS"

        return PolicyDecision(
            decision=decision,
            blocking=blocking,
            warnings=warnings,
            ignored=ignored,
            counts=counts
        )