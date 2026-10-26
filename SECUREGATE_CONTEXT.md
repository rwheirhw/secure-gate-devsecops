# SecureGate Project Context

## 1. Project Identity

**Project name:** SecureGate

**Current working title:**

> Automated Vulnerability Detection and Security Gating in Containerized Applications: A Case Study of Enterprise DevSecOps

The project is being repositioned so that it does **not** become a smaller copy of the uploaded/reference project **SecureBuild: Continuous Software Supply-Chain Security & Automated Remediation**.

### Final direction

SecureGate is a:

> **DevSecOps deployment security assurance system that evaluates container artifacts and Kubernetes deployment configurations against security policies, calculates deployment risk, and continuously detects security-posture drift after deployment.**

The project's distinctive contribution is **deployment security posture and policy enforcement**, not building another vulnerability scanner or software supply-chain platform.

---

# 2. Why the Scope Is Being Changed

SecureBuild already covers:

- Multi-vector security scanning
- SAST
- Secret detection
- Dependency scanning
- Container vulnerability scanning
- SBOM generation
- Post-deployment CVE correlation
- Risk scoring
- Policy-as-code gates
- Automated remediation
- Dashboards

Therefore SecureGate must NOT evolve into:

- Another SBOM platform
- Another CVE correlation platform
- Another dependency remediation platform
- Another multi-scanner supply-chain platform
- A SOC/SIEM/runtime threat-detection platform

SecureGate can still consume vulnerability results from Trivy, but vulnerability detection is an **input** rather than the project's defining identity.

---

# 3. Final Conceptual Boundary

## SecureBuild

Primary question:

> Is my software supply chain secure?

Focus:

```text
Source
  -> Dependencies
  -> SBOM
  -> Vulnerabilities
  -> CVE correlation
  -> Risk
  -> Policy
  -> Remediation
```

## SecureGate

Primary question:

> Is this containerized application safe and compliant to deploy in this environment?

Focus:

```text
Container Image
       +
Kubernetes Deployment Configuration
       +
Security Policy
       ↓
Risk Assessment
       ↓
PASS / WARN / BLOCK
       ↓
Deployment
       ↓
Post-Deployment Security Posture Monitoring
       ↓
Configuration Drift Detection
       ↓
Risk Recalculation
```

---

# 4. Final SecureGate Architecture

```text
                         GIT
                          |
                          v
                       JENKINS
                          |
                 +--------+--------+
                 |                 |
                 v                 v
             DOCKER BUILD      K8s MANIFEST
                 |                 |
                 v                 v
               TRIVY         K8s INSPECTOR
                 |                 |
                 +--------+--------+
                          |
                          v
                   SECUREGATE CORE
                          |
              +-----------+-----------+
              |           |           |
              v           v           v
          FINDINGS      RISK       POLICY
           ENGINE      ENGINE      ENGINE
              |           |           |
              +-----------+-----------+
                          |
                          v
                   PASS / WARN / BLOCK
                          |
                         PASS
                          |
                          v
                      REGISTRY
                          |
                          v
                     KUBERNETES
                          |
                          v
                APPROVED BASELINE
                          |
                          v
             POST-DEPLOYMENT MONITOR
                          |
                          v
                  DRIFT DETECTION
                          |
                          v
                    RISK RECALC
                          |
                    +-----+-----+
                    |           |
                    v           v
                  ALERT      RESPONSE
```

---

# 5. What SecureGate WILL Cover

## A. Artifact Security

Trivy remains part of the system.

Trivy answers:

> What known vulnerabilities exist in this container image?

SecureGate consumes those findings.

SecureGate does NOT need to implement its own vulnerability scanner.

Example:

```text
Trivy
  -> CVE findings
  -> SecureGate
  -> Policy evaluation
```

---

## B. Deployment Security

SecureGate independently inspects Kubernetes deployment configuration.

Initial security checks should include:

### Container security

- `privileged`
- `runAsUser`
- `runAsNonRoot`
- `allowPrivilegeEscalation`
- `hostNetwork`
- `hostPID`
- `hostIPC`
- Linux capabilities

### Secret handling

- Plaintext secrets in environment variables
- Kubernetes Secret references

### Network exposure

- ClusterIP
- NodePort
- LoadBalancer
- Ingress/external exposure

### Resource controls

- CPU limits
- Memory limits
- CPU requests
- Memory requests

### Image controls

- Mutable image tags
- `latest`
- Image digest requirements

Do not initially implement dozens of checks. Start with roughly 10 strong, explainable security rules.

---

# 6. Security Finding Model

The current project is heavily centered around:

```text
Vulnerability
```

This must change.

The target abstraction is:

```text
Finding
```

A finding may originate from:

```text
VULNERABILITY
DEPLOYMENT_CONFIG
NETWORK_EXPOSURE
SECRET_EXPOSURE
PRIVILEGE
DRIFT
```

Conceptually:

```text
Finding
├── id
├── source
├── category
├── severity
├── resource
├── message
├── evidence
└── metadata
```

A Trivy CVE becomes:

```text
source   = trivy
category = vulnerability
```

A Kubernetes violation such as `privileged: true` becomes:

```text
source   = kubernetes
category = privilege
```

This generic finding model is the key Phase 1 architectural refactor.

---

# 7. Policy Engine

The existing policy engine should be retained and generalized.

Current model:

```text
CRITICAL -> BLOCK
HIGH     -> BLOCK
MEDIUM   -> WARN
LOW      -> ALLOW
```

Target model:

```yaml
vulnerabilities:
  CRITICAL: BLOCK
  HIGH: BLOCK
  MEDIUM: WARN
  LOW: ALLOW

deployment:
  privileged: BLOCK
  run_as_root: BLOCK
  privilege_escalation: BLOCK
  host_network: BLOCK
  plaintext_secret: BLOCK
  missing_resource_limits: WARN
  external_service: WARN
```

The exact configuration format can remain JSON initially if that reduces implementation risk. YAML is optional and should not be introduced merely for appearance.

---

# 8. Risk Scoring

SecureGate WILL quantify risk.

However, it must NOT copy SecureBuild's risk formula.

SecureBuild's risk model considers vulnerability severity, environment exposure, dependency freshness and license risk.

SecureGate's risk should represent:

> **Deployment security posture**

Conceptually:

```text
Artifact Risk
      +
Deployment Risk
      +
Drift Risk
      =
SecureGate Risk
```

Potential report:

```text
Artifact Risk       : 35
Deployment Risk     : 45
Total Risk          : 80/100

Decision            : BLOCK
```

Do not invent arbitrary mathematical complexity. First build the finding and policy system; then define a transparent weighted scoring model based on the actual security controls.

---

# 9. Approved Security Baseline

When a deployment passes SecureGate, record the approved security posture.

Example:

```json
{
  "deployment": "secure-app",
  "image_digest": "sha256:...",
  "privileged": false,
  "run_as_non_root": true,
  "host_network": false,
  "host_pid": false,
  "external_exposure": false,
  "risk_score": 18
}
```

This represents:

> What SecureGate approved.

This baseline is later used for post-deployment drift detection.

---

# 10. Post-Deployment Monitoring

Post-deployment monitoring IS part of SecureGate.

However, it is specifically:

> **Security posture/configuration monitoring**

It is NOT general observability or SOC monitoring.

Monitor:

- SecurityContext changes
- Privilege changes
- User/root configuration
- Host namespace access
- Capabilities
- Secret configuration
- Service exposure
- Image digest changes
- RBAC posture
- Security-related resource constraints

Do NOT expand this into:

- CPU monitoring
- RAM monitoring
- HTTP latency
- Generic application logs
- SIEM
- Network packet analytics
- CVE feed monitoring
- General Kubernetes observability

The core comparison is:

```text
APPROVED STATE
      vs
CURRENT STATE
      ↓
SECURITY DRIFT?
```

---

# 11. Drift Detection

Example:

Approved:

```text
privileged = false
runAsNonRoot = true
hostNetwork = false
```

Current:

```text
privileged = true
runAsNonRoot = true
hostNetwork = false
```

SecureGate reports:

```text
SECURITY POSTURE DRIFT

Resource: secure-app

Changed:
privileged: false -> true

Risk:
CRITICAL
```

The system then recalculates the security risk.

---

# 12. Response Model

Keep response controlled.

Initial model:

```text
LOW DRIFT
    -> record

MEDIUM DRIFT
    -> alert

HIGH DRIFT
    -> mark deployment non-compliant

CRITICAL DRIFT
    -> alert + security response
```

Possible later response:

- Block future deployment
- Restore last approved configuration
- Roll back to last approved deployment

Do NOT initially build autonomous vulnerability patching or automated dependency PR generation.

---

# 13. What We KEEP

The existing work is NOT being discarded.

Keep:

- Docker
- Jenkins
- Trivy
- Trivy JSON generation
- Trivy parser
- Analyzer concept
- Policy engine concept
- Reporter
- Typer CLI
- Tests
- Existing CI/CD PASS/BLOCK behavior

The current pipeline:

```text
Jenkins
  -> Docker build
  -> Trivy
  -> JSON
  -> SecureGate
  -> PASS/BLOCK
```

becomes the artifact-security component of the larger system.

---

# 14. What Gets Refactored

## `models.py`

Current:

```text
Vulnerability
ScanResult
PolicyDecision
```

Target:

```text
Finding
ScanResult / source result as needed
PolicyDecision
RiskAssessment
SecurityBaseline
DriftEvent
```

Do not add all models immediately. Phase 1 only needs the generic `Finding` transition.

---

## `scanner.py`

Current location:

```text
securegate/scanner.py
```

Target conceptual location:

```text
securegate/scanners/trivy.py
```

Responsibility:

```text
Run Trivy
    ↓
Obtain report
    ↓
Produce findings
```

It should not contain the policy.

---

## `parser.py`

Current:

```text
Trivy JSON
    ↓
Vulnerability objects
```

Target:

```text
Trivy JSON
    ↓
Finding objects
```

---

## `analyzer.py`

Current:

```text
Analyzer
    ↓
CVEs
```

Target eventually:

```text
VulnerabilityAnalyzer
DeploymentAnalyzer
```

Do not split it prematurely if the generic Finding refactor can be done cleanly first.

---

## `policy.py`

Keep the core.

Change from:

```text
severity -> action
```

toward:

```text
finding category/type/rule -> action
```

It must continue supporting vulnerability severity policies.

---

# 15. What We Explicitly DO NOT Add

These are deliberately outside SecureGate's scope:

- SBOM platform
- Continuous NVD/OSV CVE correlation
- CVE monitoring daemon
- Dependency freshness engine
- License-risk platform
- Automated dependency remediation
- Automatic pull-request generation
- Full SAST platform
- Gitleaks ecosystem
- Grype ecosystem
- Enterprise supply-chain dashboard
- SIEM
- SOC functionality
- Generic runtime threat detection
- Packet-level network monitoring
- Generic Kubernetes observability

The purpose is differentiation, not arbitrary feature reduction.

---

# 16. Target Repository Structure

Do not create every directory immediately. This is the target architecture.

```text
SecureGate/
│
├── securegate.py
├── Jenkinsfile
│
├── config/
│   └── policy.json
│
├── securegate/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   └── trivy.py
│   │
│   ├── inspectors/
│   │   ├── __init__.py
│   │   └── kubernetes.py
│   │
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── vulnerability.py
│   │   └── deployment.py
│   │
│   ├── policy/
│   │   ├── __init__.py
│   │   └── engine.py
│   │
│   └── reporter.py
│
├── tests/
│   ├── test_trivy.py
│   ├── test_kubernetes.py
│   ├── test_policy.py
│   └── test_integration.py
│
└── reports/
```

This is a design target, not an instruction to refactor everything at once.

---

# 17. PHASE 1 — CURRENT TASK

## Phase 1A: Baseline

Before changing code:

1. Run the current SecureGate CLI.
2. Run the current Trivy scan.
3. Run the current tests.
4. Confirm the current Jenkins security gate works.
5. Record the current behavior.

Nothing should be changed until the baseline is known-good.

---

## Phase 1B: Generic Finding Refactor

The ONLY architectural change in the first implementation step:

```text
CURRENT

Trivy
  ↓
Vulnerability
  ↓
Policy
  ↓
PASS/BLOCK
```

becomes:

```text
TARGET

Trivy
  ↓
Finding
  ↓
Policy
  ↓
PASS/BLOCK
```

The output and behavior must remain functionally equivalent.

### Acceptance criteria

After Phase 1B:

- Trivy still runs.
- Trivy JSON is still parsed.
- Vulnerability information is preserved.
- Existing policy rules still work.
- PASS/BLOCK behavior is unchanged.
- Existing tests pass.
- Jenkins still receives the correct exit code.
- No Kubernetes functionality is introduced yet.

Only after this passes should Kubernetes deployment findings be added.

---

# 18. Development Principle

Do not make multiple architectural changes simultaneously.

Preferred sequence:

```text
Generic Finding
      ↓
Tests
      ↓
Trivy adapter
      ↓
Tests
      ↓
Kubernetes inspector
      ↓
Tests
      ↓
Unified policy
      ↓
Risk
      ↓
Baseline
      ↓
Drift monitoring
```

At every stage, preserve a working system.

---

# 19. Codex / VS Code Instructions

When continuing this project with Codex:

1. Read this file completely.
2. Inspect the existing repository before modifying anything.
3. Do not assume the repository matches the target structure in this document.
4. Do not delete working code merely to match the target structure.
5. Do not add features outside the current phase.
6. For Phase 1, focus ONLY on the `Vulnerability -> Finding` refactor.
7. Preserve existing behavior.
8. Run tests after modifications.
9. Explain architectural changes before making broad changes.
10. Do not introduce Kubernetes, risk scoring, drift monitoring, dashboards, SBOMs, SAST, remediation, or additional scanners during Phase 1.

## Immediate Codex task

> Inspect the existing SecureGate repository and establish the Phase 1A baseline. Do not modify the code yet. Report the current structure, available tests, current CLI commands, and any discrepancies between the repository and this context document.

After the baseline is understood:

> Implement Phase 1B: refactor the internal vulnerability representation into a generic `Finding` model while preserving current Trivy scanning, policy evaluation, reporting, CLI behavior, and Jenkins exit-code behavior. Run the existing tests and add/update focused tests for the refactor. Do not implement Kubernetes inspection or any Phase 2+ features.

---

# 20. Non-Negotiable Scope Boundary

SecureGate should remain:

> **DevSecOps deployment security assurance**

It should NOT become:

> A software supply-chain platform

and should NOT become:

> A SOC/runtime threat-detection platform.

The distinctive loop is:

```text
ASSESS
  ↓
POLICY
  ↓
DEPLOY
  ↓
BASELINE
  ↓
MONITOR SECURITY POSTURE
  ↓
DETECT DRIFT
  ↓
REASSESS RISK
  ↓
RESPOND
```

That is the project.
