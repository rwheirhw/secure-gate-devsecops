# SecureGate

> **DevSecOps Deployment Security Assurance System**
>
> Automated container artifact evaluation and Kubernetes deployment security assurance. Enforces deployment security controls, evaluates policy-as-code (JSON & YAML), calculates transparent posture risk metrics, and detects post-deployment configuration drift.

---

## 1. Dual Operational Paths

SecureGate provides two distinct consumption paths:

```
                      +-----------------------------+
                      |         SecureGate          |
                      +--------------+--------------+
                                     |
              +----------------------+----------------------+
              |                                             |
              v                                             v
     [Automated CI/CD Path]                      [Administrator UI Path]
• Direct CLI invocation in Jenkins          • Web Dashboard (`securegate serve`)
• Headless, deterministic exit codes        • Interactive YAML Workbench
• Reports saved to `reports/*.json`         • Visual Drift & Baseline Explorer
• Halts deployments on BLOCK violations     • Real-time Policy & Audit Inspector
```

1. **Automated CI/CD Pipeline (Jenkins / Git Hooks)**:
   The CI agent executes the installed CLI (`securegate assess ...`). It operates headlessly with zero human intervention and deterministic exit codes (`0` for PASS, `1` for BLOCK). It does **not** depend on a web browser or dashboard server.

2. **Administrator Interactive Dashboard (`securegate serve` or `securegate dashboard`)**:
   Administrators and developers can launch an interactive visual workbench (default `http://127.0.0.1:8088/`). The command opens the page in the default browser unless `--no-open` is passed.

---

## 2. Policy Precedence & Risk Scoring

> [!IMPORTANT]
> **Mandatory Policy Controls Take Absolute Precedence Over Numerical Scores:**
> A deployment is **BLOCKED immediately** if any mandatory policy control fails (such as `privileged: true`, `runAsUser: 0`, or an unapproved `CRITICAL` CVE). A low numerical risk score does **not** override a mandatory block rule.

### Transparent Posture Scoring Model
```
Total Posture Risk (0 - 100) = min(100, Artifact Risk [max 40] + Deployment Risk [max 45] + Drift Risk [max 30])
```

- **Artifact Risk (max 40 pts)**: Weighted Trivy vulnerability findings.
- **Deployment Risk (max 45 pts)**: Weighted Kubernetes security control findings (`privilege: x1.3`, `secret_exposure: x1.2`, `network_exposure: x1.0`, `resource_controls: x0.7`).
- **Drift Risk (max 30 pts)**: Weighted posture deviation from approved baseline.

---

## 3. Quick Start & CLI Reference

### Installation

Install once. After that, use the `securegate` command — do not run `python securegate.py`.

```bash
python -m pip install -e .
securegate version
```

`python -m securegate` works as well if the `securegate` script is not on `PATH`.

### Web dashboard

```bash
securegate serve
# or:
securegate dashboard
```

This starts the local UI and opens it in your browser. Use `--no-open` to print the URL only, and `--port 8080` to pick a port.

### CLI Commands

| Command | Purpose | Example |
|:---|:---|:---|
| `serve` / `dashboard` | Launch web dashboard (opens browser) | `securegate serve` |
| `assess` | Combined Artifact + K8s evaluation | `securegate assess reports/scan.json k8s/enterprise-sample.yaml --policy config/policy.yaml` |
| `inspect` | Inspect K8s deployment manifests | `securegate inspect k8s/enterprise-sample.yaml --policy config/policy.yaml` |
| `evaluate` | Evaluate existing Trivy scan report | `securegate evaluate reports/scan.json --policy config/policy.yaml` |
| `baseline` | Save approved security baseline | `securegate baseline k8s/enterprise-sample.yaml -o baselines/production.json` |
| `drift` | Detect posture drift against baseline | `securegate drift baselines/production.json k8s/enterprise-sample.yaml` |
| `scan` | Scan container image via Trivy | `securegate scan secure-app:1.0.0 -o reports/scan.json` |
| `version` | Display version info | `securegate version` |

---

## 4. Policy Configuration (`config/policy.yaml` or `policy.json`)

SecureGate supports both **YAML** and **JSON** policy files:

```yaml
severity_policy:
  CRITICAL: BLOCK
  HIGH: BLOCK
  MEDIUM: WARN
  LOW: ALLOW
  UNKNOWN: WARN

finding_policy:
  K8S_PRIVILEGED_CONTAINER: BLOCK
  K8S_RUN_AS_ROOT: BLOCK
  K8S_RUN_AS_NON_ROOT_FALSE: BLOCK
  K8S_PRIVILEGE_ESCALATION: BLOCK
  K8S_HOST_NETWORK: BLOCK
  K8S_HOST_PID: BLOCK
  K8S_HOST_IPC: BLOCK
  K8S_ADDED_CAPABILITIES: BLOCK
  K8S_PLAINTEXT_SECRET_ENV: BLOCK
  K8S_MISSING_RESOURCE_CONTROLS: WARN
  K8S_EXTERNAL_SERVICE: WARN
  K8S_INGRESS_EXPOSURE: WARN
  K8S_IMAGE_DIGEST_MISSING: WARN
  K8S_MUTABLE_IMAGE_TAG: WARN

category_policy:
  privilege: BLOCK
  secret_exposure: BLOCK
  network_exposure: WARN
  resource_controls: WARN
  deployment_config: WARN

max_allowed:
  CRITICAL: 0
  HIGH: 0
```

---

## 5. Web Dashboard Architecture

The dashboard is served locally without external server dependencies via standard library `http.server`:
- **Port:** Default `8080`
- **Frontend:** Vanilla HTML5 + CSS3 (Glassmorphic dark design) + Vanilla JavaScript
- **API Endpoints:**
  - `POST /api/assess`: In-memory and file-based combined evaluation.
  - `POST /api/inspect`: In-memory YAML manifest inspection.
  - `GET /api/reports`: Lists historical CI/CD JSON reports generated by Jenkins.
  - `GET /api/baselines`: Lists saved approved baselines.
  - `POST /api/drift`: Calculates field-level drift against an approved baseline.
  - `GET /api/samples`: Loads built-in hardened and insecure manifests.

---

## 6. Testing

The current test suite contains 55 tests and runs with standard `pytest`:

```bash
python -m pytest -v
```

For the next hardening priorities and the boundary with SAT and identity
capabilities, see
[DEVSECOPS_DEFENSIBILITY_ROADMAP.md](./DEVSECOPS_DEFENSIBILITY_ROADMAP.md).
