from textwrap import dedent

import pytest

from securegate.inspectors.kubernetes import KubernetesInspector


def write_manifest(tmp_path, content):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        dedent(content),
        encoding="utf-8",
    )
    return manifest


def rule_ids(findings):
    return {
        finding.id
        for finding in findings
    }


def test_kubernetes_inspector_flags_insecure_deployment_controls(tmp_path):
    manifest = write_manifest(
        tmp_path,
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: insecure-app
          namespace: production
        spec:
          template:
            spec:
              hostNetwork: true
              hostPID: true
              hostIPC: true
              containers:
                - name: app
                  image: nginx:latest
                  securityContext:
                    privileged: true
                    allowPrivilegeEscalation: true
                    runAsUser: 0
                    runAsNonRoot: false
                    capabilities:
                      add:
                        - NET_ADMIN
                  env:
                    - name: DATABASE_PASSWORD
                      value: plain-text-password
        """,
    )

    findings = KubernetesInspector(str(manifest)).inspect()

    assert rule_ids(findings) == {
        "K8S_HOST_NETWORK",
        "K8S_HOST_PID",
        "K8S_HOST_IPC",
        "K8S_PRIVILEGED_CONTAINER",
        "K8S_PRIVILEGE_ESCALATION",
        "K8S_RUN_AS_ROOT",
        "K8S_RUN_AS_NON_ROOT_FALSE",
        "K8S_ADDED_CAPABILITIES",
        "K8S_PLAINTEXT_SECRET_ENV",
        "K8S_MISSING_RESOURCE_CONTROLS",
        "K8S_IMAGE_DIGEST_MISSING",
        "K8S_MUTABLE_IMAGE_TAG",
    }
    assert {
        finding.source
        for finding in findings
    } == {"kubernetes"}
    assert all(
        finding.resource == "Deployment/production/insecure-app"
        for finding in findings
    )


def test_kubernetes_inspector_flags_external_service_and_ingress(tmp_path):
    manifest = write_manifest(
        tmp_path,
        """
        apiVersion: v1
        kind: Service
        metadata:
          name: public-service
        spec:
          type: LoadBalancer
        ---
        apiVersion: networking.k8s.io/v1
        kind: Ingress
        metadata:
          name: public-ingress
        spec: {}
        """,
    )

    findings = KubernetesInspector(str(manifest)).inspect()

    assert rule_ids(findings) == {
        "K8S_EXTERNAL_SERVICE",
        "K8S_INGRESS_EXPOSURE",
    }
    assert all(
        finding.category == "network_exposure"
        for finding in findings
    )


def test_kubernetes_inspector_allows_hardened_deployment(tmp_path):
    manifest = write_manifest(
        tmp_path,
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: secure-app
        spec:
          template:
            spec:
              securityContext:
                runAsNonRoot: true
                runAsUser: 1000
              containers:
                - name: app
                  image: example.com/secure-app@sha256:1234567890abcdef
                  securityContext:
                    privileged: false
                    allowPrivilegeEscalation: false
                    capabilities:
                      drop:
                        - ALL
                  env:
                    - name: API_TOKEN
                      valueFrom:
                        secretKeyRef:
                          name: app-token
                          key: token
                  resources:
                    requests:
                      cpu: 100m
                      memory: 128Mi
                    limits:
                      cpu: 500m
                      memory: 256Mi
        """,
    )

    assert KubernetesInspector(str(manifest)).inspect() == []


def test_kubernetes_inspector_raises_for_missing_manifest(tmp_path):
    missing_manifest = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError, match="manifest not found"):
        KubernetesInspector(str(missing_manifest)).inspect()
