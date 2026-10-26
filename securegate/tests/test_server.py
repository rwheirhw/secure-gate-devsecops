"""Tests for SecureGate REST API & Dashboard Server."""

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

import pytest

from securegate import __version__
from securegate.server import SecureGateHandler


@pytest.fixture(scope="module")
def api_server():
    """Spin up a test server instance on an ephemeral port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), SecureGateHandler)
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()


def http_get(url: str):
    req = Request(url)
    with urlopen(req) as resp:
        return resp.status, resp.headers.get("Content-Type"), resp.read()


def http_post_json(url: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def test_api_status_endpoint(api_server):
    status, ctype, body = http_get(f"{api_server}/api/status")
    assert status == 200
    assert "application/json" in ctype
    data = json.loads(body.decode("utf-8"))
    assert data["status"] == "ok"
    assert data["version"] == __version__


def test_api_samples_endpoint(api_server):
    status, ctype, body = http_get(f"{api_server}/api/samples")
    assert status == 200
    data = json.loads(body.decode("utf-8"))
    assert "enterprise_sample" in data
    assert "hardened_sample" in data


def test_api_assess_endpoint_hardened(api_server):
    hardened_yaml = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: secure-app
    spec:
      template:
        spec:
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
          containers:
            - name: app
              image: registry.example.com/app@sha256:ba5e911075d9e5b871c4c79401777f9859f518e95c1c8ec78fb564412ab4e7e6
              securityContext:
                privileged: false
                allowPrivilegeEscalation: false
                capabilities:
                  drop: ["ALL"]
              resources:
                requests:
                  cpu: 100m
                  memory: 128Mi
                limits:
                  cpu: 500m
                  memory: 256Mi
    """
    status, data = http_post_json(
        f"{api_server}/api/assess",
        {"manifest_yaml": hardened_yaml, "report_file": ""},
    )
    assert status == 200
    assert data["decision"] == "PASS"
    assert len(data["blocking_findings"]) == 0
    assert data["risk"]["deployment_risk"] == 0


def test_api_assess_endpoint_insecure(api_server):
    insecure_yaml = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: insecure-app
    spec:
      template:
        spec:
          hostNetwork: true
          containers:
            - name: app
              image: nginx:latest
              securityContext:
                privileged: true
    """
    status, data = http_post_json(
        f"{api_server}/api/assess",
        {"manifest_yaml": insecure_yaml, "report_file": ""},
    )
    assert status == 200
    assert data["decision"] == "BLOCK"
    assert len(data["blocking_findings"]) >= 2


def test_static_dashboard_serving(api_server):
    status, ctype, body = http_get(f"{api_server}/")
    assert status == 200
    assert "text/html" in ctype
    assert b"SecureGate" in body
