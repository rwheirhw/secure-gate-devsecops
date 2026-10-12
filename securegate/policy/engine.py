"""SecureGate Policy Engine.

Evaluates security findings against configurable policies and produces
deployment decisions (PASS / WARN / BLOCK).
"""

import json
from pathlib import Path

import yaml

from ..models import PolicyDecision


VALID_ACTIONS = {
    "ALLOW",
    "WARN",
    "BLOCK",
}


class PolicyEngine:
    """Evaluates findings against security policies.

    Policy precedence (highest to lowest):
        1. ignored_findings / ignored_vulnerabilities — skip entirely
        2. finding_policy — match on finding.id (e.g. K8S_PRIVILEGED_CONTAINER)
        3. category_policy — match on finding.category (e.g. privilege)
        4. severity_policy — match on finding.severity (e.g. CRITICAL)

    Additionally, ``max_allowed`` rules promote findings to BLOCK when the
    effective count for a severity exceeds a threshold.
    """

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
            encoding="utf-8",
        ) as file:
            if self.policy_path.suffix.lower() in {".yaml", ".yml"}:
                policy = yaml.safe_load(file)
            else:
                try:
                    policy = json.load(file)
                except json.JSONDecodeError:
                    file.seek(0)
                    policy = yaml.safe_load(file)

        if not isinstance(policy, dict):
            raise ValueError("Policy must be a JSON or YAML object/mapping")

        severity_policy = policy.get(
            "severity_policy",
            {},
        )

        self._validate_actions(
            "severity_policy",
            severity_policy,
        )
        self._validate_actions(
            "finding_policy",
            policy.get("finding_policy", {}),
        )
        self._validate_actions(
            "category_policy",
            policy.get("category_policy", {}),
        )

        return policy

    def _validate_actions(self, policy_name, policy_section):
        for rule, action in policy_section.items():
            if action not in VALID_ACTIONS:
                raise ValueError(
                    f"Invalid policy action for {policy_name}.{rule}: "
                    f"{action}"
                )

    def evaluate(self, findings):
        """Evaluate a list of findings and return a PolicyDecision."""
        findings = list(findings)

        severity_policy = self.policy.get(
            "severity_policy",
            {},
        )
        finding_policy = self.policy.get(
            "finding_policy",
            {},
        )
        category_policy = self.policy.get(
            "category_policy",
            {},
        )

        ignored_ids = set(
            self.policy.get(
                "ignored_vulnerabilities",
                [],
            )
        )
        ignored_ids.update(
            self.policy.get(
                "ignored_findings",
                [],
            )
        )

        blocking = []
        warnings = []
        ignored = []

        for finding in findings:

            if finding.id in ignored_ids:
                ignored.append(finding)
                continue

            action = self._action_for(
                finding,
                finding_policy,
                category_policy,
                severity_policy,
            )

            if action == "BLOCK":
                blocking.append(finding)

            elif action == "WARN":
                warnings.append(finding)

        counts = {}

        for finding in findings:
            severity = finding.severity
            counts[severity] = counts.get(
                severity,
                0,
            ) + 1

        # Apply explicit maximum-count rules.
        max_allowed = self.policy.get(
            "max_allowed",
            {},
        )

        for severity, maximum in max_allowed.items():

            effective_count = sum(
                1
                for finding in findings
                if (
                    finding.severity == severity
                    and finding.id
                    not in ignored_ids
                )
            )

            if effective_count > maximum:

                # Avoid duplicate entries.
                for finding in findings:
                    if (
                        finding.severity == severity
                        and finding.id
                        not in ignored_ids
                        and finding
                        not in blocking
                    ):
                        blocking.append(finding)

        decision = "BLOCK" if blocking else "PASS"

        return PolicyDecision(
            decision=decision,
            blocking=blocking,
            warnings=warnings,
            ignored=ignored,
            counts=counts,
        )

    def _action_for(
        self,
        finding,
        finding_policy,
        category_policy,
        severity_policy,
    ):
        if finding.id in finding_policy:
            return finding_policy[finding.id]

        if finding.category in category_policy:
            return category_policy[finding.category]

        return severity_policy.get(
            finding.severity,
            "WARN",
        )
