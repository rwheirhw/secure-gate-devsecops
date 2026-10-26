import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import DriftEvent, Finding, RiskAssessment, SecurityBaseline


class BaselineStore:
    def save(
        self,
        output_path: str,
        manifest: str,
        posture: dict[str, Any],
        risk: RiskAssessment,
    ) -> Path:
        output = Path(output_path)
        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        baseline = SecurityBaseline(
            manifest=manifest,
            approved_at=datetime.now(timezone.utc).isoformat(),
            risk=risk,
            posture=posture,
        )

        with output.open("w", encoding="utf-8") as file:
            json.dump(
                asdict(baseline),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output

    def load(
        self,
        baseline_path: str,
    ) -> dict[str, Any]:
        path = Path(baseline_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Security baseline not found: {path}"
            )

        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Security baseline must be a JSON object")

        posture = data.get("posture")

        if not isinstance(posture, dict):
            raise ValueError("Security baseline is missing posture data")

        return data


class DriftDetector:
    def detect(
        self,
        approved_posture: dict[str, Any],
        current_posture: dict[str, Any],
    ) -> list[DriftEvent]:
        approved_resources = self._resources_by_name(approved_posture)
        current_resources = self._resources_by_name(current_posture)
        events = []

        for resource in sorted(
            set(approved_resources)
            | set(current_resources)
        ):
            approved = approved_resources.get(resource)
            current = current_resources.get(resource)

            if approved is None:
                events.append(
                    self._event(
                        resource=resource,
                        field="resource",
                        approved_value=None,
                        current_value="added",
                    )
                )
                continue

            if current is None:
                events.append(
                    self._event(
                        resource=resource,
                        field="resource",
                        approved_value="present",
                        current_value=None,
                    )
                )
                continue

            events.extend(
                self._compare_values(
                    resource=resource,
                    path="",
                    approved=approved,
                    current=current,
                )
            )

        return events

    def findings_for(
        self,
        drift_events: list[DriftEvent],
    ) -> list[Finding]:
        return [
            Finding(
                id=event.id,
                source="drift",
                category="drift",
                severity=event.severity,
                resource=event.resource,
                message=event.message,
                evidence={
                    "field": event.field,
                    "approved": event.approved_value,
                    "current": event.current_value,
                },
                metadata={
                    "field": event.field,
                },
            )
            for event in drift_events
        ]

    def _resources_by_name(
        self,
        posture: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        resources = posture.get("resources", [])

        if not isinstance(resources, list):
            return {}

        return {
            resource["resource"]: resource
            for resource in resources
            if isinstance(resource, dict)
            and "resource" in resource
        }

    def _compare_values(
        self,
        resource: str,
        path: str,
        approved,
        current,
    ) -> list[DriftEvent]:
        if approved == current:
            return []

        if isinstance(approved, dict) and isinstance(current, dict):
            events = []

            for key in sorted(
                set(approved)
                | set(current)
            ):
                child_path = (
                    f"{path}.{key}"
                    if path
                    else str(key)
                )
                events.extend(
                    self._compare_values(
                        resource,
                        child_path,
                        approved.get(key),
                        current.get(key),
                    )
                )

            return events

        if isinstance(approved, list) and isinstance(current, list):
            approved_normalized = self._normalize_list(approved)
            current_normalized = self._normalize_list(current)

            if approved_normalized == current_normalized:
                return []

            return [
                self._event(
                    resource=resource,
                    field=path,
                    approved_value=approved,
                    current_value=current,
                )
            ]

        return [
            self._event(
                resource=resource,
                field=path,
                approved_value=approved,
                current_value=current,
            )
        ]

    def _normalize_list(
        self,
        values: list[Any],
    ) -> list[Any]:
        return sorted(
            values,
            key=lambda value: json.dumps(
                value,
                sort_keys=True,
                default=str,
            ),
        )

    def _event(
        self,
        resource: str,
        field: str,
        approved_value,
        current_value,
    ) -> DriftEvent:
        severity = self._severity_for(
            field,
            approved_value,
            current_value,
        )
        event_id = (
            "DRIFT_"
            + field.upper()
            .replace(".", "_")
            .replace("-", "_")
        )

        return DriftEvent(
            id=event_id,
            resource=resource,
            field=field,
            approved_value=approved_value,
            current_value=current_value,
            severity=severity,
            message=(
                f"Security posture drift detected for {field}: "
                f"{approved_value!r} -> {current_value!r}"
            ),
        )

    def _severity_for(
        self,
        field: str,
        approved_value,
        current_value,
    ) -> str:
        sensitive_fields = {
            "privileged",
            "allowPrivilegeEscalation",
            "runAsUser",
            "runAsNonRoot",
            "hostNetwork",
            "hostPID",
            "hostIPC",
            "capabilitiesAdd",
            "plaintextSecretEnv",
        }

        if field == "resource":
            return "HIGH"

        if any(
            sensitive in field
            for sensitive in sensitive_fields
        ):
            if (
                current_value is True
                or current_value == 0
                or current_value == "0"
            ):
                return "CRITICAL"

            return "HIGH"

        if "image" in field:
            return "HIGH"

        return "MEDIUM"
