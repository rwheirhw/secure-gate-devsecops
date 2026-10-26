import re
from pathlib import Path
from typing import Any

import yaml

from ..models import Finding


SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)

WORKLOAD_TEMPLATE_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
}


class KubernetesInspector:
    def __init__(
        self,
        manifest_path: str | Path | None = None,
        yaml_content: str | None = None,
    ):
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self.yaml_content = yaml_content

    def inspect(self) -> list[Finding]:
        findings = []

        for document, source_path in self._load_documents():
            if not isinstance(document, dict):
                continue

            kind = str(
                document.get("kind", "Unknown")
            )

            if kind == "Service":
                findings.extend(
                    self._inspect_service(document, source_path)
                )
                continue

            if kind == "Ingress":
                findings.append(
                    self._finding(
                        rule_id="K8S_INGRESS_EXPOSURE",
                        category="network_exposure",
                        severity="MEDIUM",
                        resource=self._resource_name(document),
                        message="Ingress exposes the workload externally.",
                        evidence={
                            "kind": kind,
                            "name": self._name(document),
                        },
                        source_path=source_path,
                    )
                )
                continue

            pod_spec = self._pod_spec(document)

            if not pod_spec:
                continue

            findings.extend(
                self._inspect_pod_security(document, pod_spec, source_path)
            )
            findings.extend(
                self._inspect_containers(document, pod_spec, source_path)
            )

        return findings

    def posture(self) -> dict[str, Any]:
        resources = []

        for document, source_path in self._load_documents():
            if not isinstance(document, dict):
                continue

            resource = {
                "resource": self._resource_name(document),
                "kind": str(document.get("kind", "Unknown")),
                "name": self._name(document),
                "namespace": (
                    (document.get("metadata") or {})
                    .get("namespace")
                ),
                "file": str(source_path),
            }

            kind = resource["kind"]

            if kind == "Service":
                resource["service"] = self._service_posture(document)
            elif kind == "Ingress":
                resource["ingress"] = {
                    "external_exposure": True,
                }
            else:
                pod_spec = self._pod_spec(document)

                if pod_spec:
                    resource["pod"] = self._pod_posture(pod_spec)

            resources.append(resource)

        resources.sort(
            key=lambda item: item["resource"]
        )

        return {
            "resources": resources,
        }

    def _load_documents(self):
        if self.yaml_content is not None:
            source = self.manifest_path or Path("inline-manifest.yaml")
            for document in yaml.safe_load_all(self.yaml_content):
                if isinstance(document, dict):
                    yield document, source
            return

        if self.manifest_path is None or not self.manifest_path.exists():
            raise FileNotFoundError(
                f"Kubernetes manifest not found: {self.manifest_path}"
            )

        for path in self._manifest_paths():
            with path.open("r", encoding="utf-8") as file:
                for document in yaml.safe_load_all(file):
                    if isinstance(document, dict):
                        yield document, path

    def _service_posture(
        self,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        spec = document.get("spec") or {}
        service_type = spec.get("type", "ClusterIP")

        return {
            "type": service_type,
            "external_exposure": service_type in {
                "NodePort",
                "LoadBalancer",
            },
        }

    def _pod_posture(
        self,
        pod_spec: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "hostNetwork": bool(
                pod_spec.get("hostNetwork", False)
            ),
            "hostPID": bool(
                pod_spec.get("hostPID", False)
            ),
            "hostIPC": bool(
                pod_spec.get("hostIPC", False)
            ),
            "securityContext": self._selected_security_context(
                pod_spec.get("securityContext") or {}
            ),
            "containers": {
                self._container_name(container): self._container_posture(
                    container
                )
                for container in self._containers(pod_spec)
            },
        }

    def _container_posture(
        self,
        container: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "name": self._container_name(container),
            "image": str(
                container.get("image", "")
            ),
            "securityContext": self._selected_security_context(
                container.get("securityContext") or {}
            ),
            "resources": container.get("resources") or {},
            "secretReferences": self._secret_references(container),
            "plaintextSecretEnv": self._plaintext_secret_env(container),
        }

    def _container_name(
        self,
        container: dict[str, Any],
    ) -> str:
        return str(
            container.get("name", "unknown")
        )

    def _selected_security_context(
        self,
        security_context: dict[str, Any],
    ) -> dict[str, Any]:
        capabilities = security_context.get("capabilities") or {}

        return {
            "privileged": security_context.get("privileged"),
            "allowPrivilegeEscalation": security_context.get(
                "allowPrivilegeEscalation"
            ),
            "runAsUser": security_context.get("runAsUser"),
            "runAsNonRoot": security_context.get("runAsNonRoot"),
            "capabilitiesAdd": capabilities.get("add") or [],
            "capabilitiesDrop": capabilities.get("drop") or [],
        }

    def _secret_references(
        self,
        container: dict[str, Any],
    ) -> list[dict[str, str]]:
        references = []

        for env_var in container.get("env", []) or []:
            if not isinstance(env_var, dict):
                continue

            value_from = env_var.get("valueFrom") or {}
            secret_key_ref = value_from.get("secretKeyRef")

            if not secret_key_ref:
                continue

            references.append(
                {
                    "env": str(env_var.get("name", "")),
                    "secret": str(secret_key_ref.get("name", "")),
                    "key": str(secret_key_ref.get("key", "")),
                }
            )

        return sorted(
            references,
            key=lambda item: (
                item["env"],
                item["secret"],
                item["key"],
            ),
        )

    def _plaintext_secret_env(
        self,
        container: dict[str, Any],
    ) -> list[str]:
        names = []

        for env_var in container.get("env", []) or []:
            if not isinstance(env_var, dict):
                continue

            name = str(
                env_var.get("name", "")
            )

            if "value" in env_var and SECRET_NAME_PATTERN.search(name):
                names.append(name)

        return sorted(names)

    def _manifest_paths(self) -> list[Path]:
        if self.manifest_path.is_file():
            return [self.manifest_path]

        if not self.manifest_path.is_dir():
            raise ValueError(
                f"Kubernetes manifest path is not a file or directory: "
                f"{self.manifest_path}"
            )

        paths = []

        for pattern in [
            "*.yaml",
            "*.yml",
            "*.json",
        ]:
            paths.extend(
                self.manifest_path.rglob(pattern)
            )

        return sorted(paths)

    def _inspect_service(
        self,
        document: dict[str, Any],
        source_path: Path,
    ) -> list[Finding]:
        spec = document.get("spec") or {}
        service_type = spec.get("type", "ClusterIP")

        if service_type not in {
            "NodePort",
            "LoadBalancer",
        }:
            return []

        return [
            self._finding(
                rule_id="K8S_EXTERNAL_SERVICE",
                category="network_exposure",
                severity="MEDIUM",
                resource=self._resource_name(document),
                message=(
                    f"Service is externally exposed as {service_type}."
                ),
                evidence={
                    "kind": "Service",
                    "name": self._name(document),
                    "type": service_type,
                },
                source_path=source_path,
            )
        ]

    def _inspect_pod_security(
        self,
        document: dict[str, Any],
        pod_spec: dict[str, Any],
        source_path: Path,
    ) -> list[Finding]:
        checks = [
            (
                "hostNetwork",
                "K8S_HOST_NETWORK",
                "network_exposure",
                "HIGH",
                "Pod uses the host network namespace.",
            ),
            (
                "hostPID",
                "K8S_HOST_PID",
                "privilege",
                "HIGH",
                "Pod uses the host PID namespace.",
            ),
            (
                "hostIPC",
                "K8S_HOST_IPC",
                "privilege",
                "HIGH",
                "Pod uses the host IPC namespace.",
            ),
        ]
        findings = []

        for field, rule_id, category, severity, message in checks:
            if pod_spec.get(field) is True:
                findings.append(
                    self._finding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        resource=self._resource_name(document),
                        message=message,
                        evidence={
                            "kind": document.get("kind"),
                            "name": self._name(document),
                            field: True,
                        },
                        source_path=source_path,
                    )
                )

        return findings

    def _inspect_containers(
        self,
        document: dict[str, Any],
        pod_spec: dict[str, Any],
        source_path: Path,
    ) -> list[Finding]:
        findings = []
        pod_security_context = pod_spec.get("securityContext") or {}

        for container in self._containers(pod_spec):
            container_name = str(
                container.get("name", "unknown")
            )
            security_context = container.get("securityContext") or {}
            resource = self._resource_name(document)

            findings.extend(
                self._inspect_container_security(
                    container_name,
                    security_context,
                    pod_security_context,
                    resource,
                    source_path,
                )
            )
            findings.extend(
                self._inspect_secret_env(
                    container,
                    container_name,
                    resource,
                    source_path,
                )
            )
            findings.extend(
                self._inspect_resource_controls(
                    container,
                    container_name,
                    resource,
                    source_path,
                )
            )
            findings.extend(
                self._inspect_image(
                    container,
                    container_name,
                    resource,
                    source_path,
                )
            )

        return findings

    def _inspect_container_security(
        self,
        container_name: str,
        security_context: dict[str, Any],
        pod_security_context: dict[str, Any],
        resource: str,
        source_path: Path,
    ) -> list[Finding]:
        findings = []

        if security_context.get("privileged") is True:
            findings.append(
                self._container_finding(
                    "K8S_PRIVILEGED_CONTAINER",
                    "privilege",
                    "CRITICAL",
                    "Container runs in privileged mode.",
                    resource,
                    container_name,
                    {"privileged": True},
                    source_path,
                )
            )

        if security_context.get("allowPrivilegeEscalation") is True:
            findings.append(
                self._container_finding(
                    "K8S_PRIVILEGE_ESCALATION",
                    "privilege",
                    "HIGH",
                    "Container allows privilege escalation.",
                    resource,
                    container_name,
                    {"allowPrivilegeEscalation": True},
                    source_path,
                )
            )

        run_as_user = self._security_value(
            "runAsUser",
            security_context,
            pod_security_context,
        )

        if run_as_user == 0 or run_as_user == "0":
            findings.append(
                self._container_finding(
                    "K8S_RUN_AS_ROOT",
                    "privilege",
                    "HIGH",
                    "Container is configured to run as root.",
                    resource,
                    container_name,
                    {"runAsUser": run_as_user},
                    source_path,
                )
            )

        run_as_non_root = self._security_value(
            "runAsNonRoot",
            security_context,
            pod_security_context,
        )

        if run_as_non_root is False:
            findings.append(
                self._container_finding(
                    "K8S_RUN_AS_NON_ROOT_FALSE",
                    "privilege",
                    "HIGH",
                    "Container explicitly disables runAsNonRoot.",
                    resource,
                    container_name,
                    {"runAsNonRoot": False},
                    source_path,
                )
            )

        capabilities_config = security_context.get("capabilities") or {}
        capabilities = capabilities_config.get("add") or []

        if isinstance(capabilities, str):
            capabilities = [capabilities]

        if capabilities:
            severity = (
                "CRITICAL"
                if "ALL" in capabilities
                else "HIGH"
            )
            findings.append(
                self._container_finding(
                    "K8S_ADDED_CAPABILITIES",
                    "privilege",
                    severity,
                    "Container adds Linux capabilities.",
                    resource,
                    container_name,
                    {"capabilities": capabilities},
                    source_path,
                )
            )

        return findings

    def _inspect_secret_env(
        self,
        container: dict[str, Any],
        container_name: str,
        resource: str,
        source_path: Path,
    ) -> list[Finding]:
        findings = []

        for env_var in container.get("env", []) or []:
            if not isinstance(env_var, dict):
                continue

            name = str(
                env_var.get("name", "")
            )

            if "value" in env_var and SECRET_NAME_PATTERN.search(name):
                findings.append(
                    self._container_finding(
                        "K8S_PLAINTEXT_SECRET_ENV",
                        "secret_exposure",
                        "HIGH",
                        "Environment variable appears to contain a plaintext secret.",
                        resource,
                        container_name,
                        {
                            "env": name,
                        },
                        source_path,
                    )
                )

        return findings

    def _inspect_resource_controls(
        self,
        container: dict[str, Any],
        container_name: str,
        resource: str,
        source_path: Path,
    ) -> list[Finding]:
        resources = container.get("resources") or {}
        limits = resources.get("limits") or {}
        requests = resources.get("requests") or {}
        missing = []

        for group_name, group in [
            ("limits", limits),
            ("requests", requests),
        ]:
            for resource_name in [
                "cpu",
                "memory",
            ]:
                if not group.get(resource_name):
                    missing.append(
                        f"{group_name}.{resource_name}"
                    )

        if not missing:
            return []

        return [
            self._container_finding(
                "K8S_MISSING_RESOURCE_CONTROLS",
                "resource_controls",
                "MEDIUM",
                "Container is missing CPU or memory requests/limits.",
                resource,
                container_name,
                {
                    "missing": missing,
                },
                source_path,
            )
        ]

    def _inspect_image(
        self,
        container: dict[str, Any],
        container_name: str,
        resource: str,
        source_path: Path,
    ) -> list[Finding]:
        image = str(
            container.get("image", "")
        )
        findings = []

        if not image:
            return findings

        has_digest = "@sha256:" in image
        image_name = image.rsplit("/", 1)[-1]
        has_tag = ":" in image_name
        uses_latest = image_name.endswith(":latest")

        if not has_digest:
            findings.append(
                self._container_finding(
                    "K8S_IMAGE_DIGEST_MISSING",
                    "deployment_config",
                    "MEDIUM",
                    "Container image is not pinned by digest.",
                    resource,
                    container_name,
                    {
                        "image": image,
                    },
                    source_path,
                )
            )

        if not has_digest and (
            not has_tag
            or uses_latest
        ):
            findings.append(
                self._container_finding(
                    "K8S_MUTABLE_IMAGE_TAG",
                    "deployment_config",
                    "MEDIUM",
                    "Container image uses a mutable tag.",
                    resource,
                    container_name,
                    {
                        "image": image,
                    },
                    source_path,
                )
            )

        return findings

    def _pod_spec(
        self,
        document: dict[str, Any],
    ) -> dict[str, Any] | None:
        kind = document.get("kind")
        spec = document.get("spec") or {}

        if kind == "Pod":
            return spec

        if kind == "CronJob":
            return (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec")
            )

        if kind in WORKLOAD_TEMPLATE_KINDS:
            return (
                spec.get("template", {})
                .get("spec")
            )

        return None

    def _containers(
        self,
        pod_spec: dict[str, Any],
    ) -> list[dict[str, Any]]:
        containers = []

        for field in [
            "initContainers",
            "containers",
        ]:
            containers.extend(
                container
                for container in pod_spec.get(field, []) or []
                if isinstance(container, dict)
            )

        return containers

    def _security_value(
        self,
        field: str,
        container_security_context: dict[str, Any],
        pod_security_context: dict[str, Any],
    ):
        if field in container_security_context:
            return container_security_context[field]

        return pod_security_context.get(field)

    def _container_finding(
        self,
        rule_id: str,
        category: str,
        severity: str,
        message: str,
        resource: str,
        container_name: str,
        evidence: dict[str, Any],
        source_path: Path,
    ) -> Finding:
        evidence = {
            **evidence,
            "container": container_name,
        }

        return self._finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            resource=resource,
            message=message,
            evidence=evidence,
            source_path=source_path,
            metadata={
                "container": container_name,
            },
        )

    def _finding(
        self,
        rule_id: str,
        category: str,
        severity: str,
        resource: str,
        message: str,
        evidence: dict[str, Any],
        source_path: Path,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            id=rule_id,
            source="kubernetes",
            category=category,
            severity=severity,
            resource=resource,
            message=message,
            evidence=evidence,
            metadata={
                "rule": rule_id,
                "file": str(source_path),
                **(metadata or {}),
            },
        )

    def _resource_name(
        self,
        document: dict[str, Any],
    ) -> str:
        kind = str(
            document.get("kind", "Unknown")
        )
        metadata = document.get("metadata") or {}
        namespace = metadata.get("namespace")
        name = self._name(document)

        if namespace:
            return f"{kind}/{namespace}/{name}"

        return f"{kind}/{name}"

    def _name(
        self,
        document: dict[str, Any],
    ) -> str:
        metadata = document.get("metadata") or {}
        return str(
            metadata.get("name", "unknown")
        )
