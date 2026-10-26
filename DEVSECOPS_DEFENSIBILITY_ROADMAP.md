# SecureGate DevSecOps Defensibility Roadmap

## Purpose

This document records whether SecureGate is complete for its stated purpose and
what should be strengthened before it is presented as an audit-ready or
production-grade DevSecOps control.

SecureGate's purpose is **deployment security assurance**:

> Determine whether a containerized application is safe and compliant to
> deploy in a target environment, then detect security-posture drift.

It is not intended to replace a project that already provides:

- SAST and source-code quality analysis
- Identity, authentication, authorization, or access governance
- Secret discovery or secret rotation
- Dependency/SBOM/CVE lifecycle management
- Runtime threat detection, SOC, or SIEM functions

Those systems remain authoritative. SecureGate should consume their signed or
machine-readable results where useful, then make deployment and posture
decisions about the Kubernetes target.

## Current completeness assessment

**Status: functionally complete as a demonstrable MVP; not complete as a
defensible production control.**

Evidence checked on 2026-10-23:

- The package has separate models for findings, risk, policy decisions,
  baselines, and drift.
- It provides CLI, Jenkins, REST/dashboard, Trivy-report ingestion, Kubernetes
  inspection, policy-as-code, risk scoring, baseline storage, and drift
  detection.
- The test suite currently passes: **55 tests passed**.
- The root README's stale “All 49 tests” statement has been corrected to 55.
- The Jenkinsfile demonstrates a happy-path pipeline, but it is not yet a
  complete security-controlled release process.

The missing work is primarily evidence quality, control reliability, deployment
integration, service hardening, and operational governance. It is not a need
to add another SAST or identity subsystem.

## Scope boundary and integration contract

### SecureGate owns

1. Container and workload deployment policy evaluation.
2. Kubernetes manifest posture inspection.
3. Image-to-deployment linkage checks, including immutable image references.
4. PASS/WARN/BLOCK decisions with explainable findings.
5. Approved-posture baseline creation and comparison.
6. Detection, classification, and reporting of deployment configuration drift.
7. Evidence packaging for release, deployment, and post-deployment decisions.

### Existing SAT/identity project owns

1. Source analysis, application testing, and code-level vulnerabilities.
2. Identity proofing, authentication, authorization, RBAC administration, and
   user/service identity lifecycle.
3. Secret discovery, issuance, storage, rotation, and revocation.
4. Dependency intelligence, SBOM ownership, remediation workflow, and
   vulnerability database correlation.

### Integration rules

- Do not duplicate those systems' scanners or identity stores.
- Accept their results through versioned adapters or an evidence manifest.
- Preserve source, timestamp, tool version, policy version, and signature or
  digest for every imported result.
- Treat imported evidence as an input to deployment policy, not as proof that
  SecureGate performed the underlying analysis.
- Define ownership and failure behavior explicitly: missing, stale, malformed,
  or unverifiable upstream evidence must not silently become a PASS.

## Priority work items

### P0 — Make the security gate trustworthy

These are prerequisites for calling the result a defensible control.

#### 1. Establish a signed, immutable evidence record

Produce one assessment bundle containing:

- source revision and build identifier
- image digest, not only a mutable tag
- Kubernetes manifest digest and rendered object list
- policy file digest and policy version
- SecureGate version and runtime version
- Trivy result digest, tool version, database timestamp, and scan status
- decision, risk breakdown, finding IDs, ignored findings, and warnings
- baseline ID/version and drift result, when applicable
- timestamp, environment, and deployment target

Store the bundle as an immutable CI artifact and make the report schema
versioned. A report must distinguish `PASS`, `WARN`, `BLOCK`, `ERROR`, and
`NOT_EVALUATED`; an execution error must never resemble a successful result.

#### 2. Fail closed at every pipeline boundary

The pipeline should stop when any required stage is skipped, malformed, stale,
or unable to prove what it evaluated. Add explicit checks for:

- Trivy exit status and non-empty, valid JSON
- policy parsing and policy schema validation
- manifest parsing and supported Kubernetes kinds
- image digest matching the image that will be pushed and deployed
- report generation and artifact publication
- deployment result and rollout health

Use a separate exit status or machine-readable status for tool failure so
operators can distinguish “blocked by policy” from “control unavailable”.

#### 3. Bind the assessed artifact to the deployed artifact

The current example pipeline builds and scans an image, then pushes a tag and
applies manifests. Add a release identity that follows the image digest
through build, scan, registry, admission/deployment, and runtime observation.
Reject a deployment when the digest assessed by SecureGate is not the digest
selected by the manifest or the cluster.

#### 4. Make policy governance auditable

Add a policy schema and validation command covering types, allowed finding IDs,
severity values, thresholds, ignored findings, and policy metadata. Require:

- policy owner and reviewer
- effective date and expiry/review date
- rationale and ticket for every exception
- bounded exception scope and compensating control
- change review and rollback history

Ignored findings must be visible in every report and must never be silently
treated as absent findings.

### P1 — Close deployment and drift assurance gaps

#### 5. Reconcile against the actual cluster

Manifest inspection is pre-deployment assurance, not proof of runtime state.
Add a read-only Kubernetes observation adapter that records the deployed
resource versions, image digests, security contexts, services, ingress, and
namespace. Compare observed state with both:

1. the approved manifest/deployment identity; and
2. the approved security baseline.

Keep this separate from identity and RBAC ownership: SecureGate verifies the
resulting workload posture and deployment identity; the identity system remains
responsible for who may change it.

#### 6. Improve baseline lifecycle

Baselines should have a stable ID, owner, environment, target selector,
manifest/image digests, policy version, approval reference, and expiry. Add
explicit baseline states such as `DRAFT`, `APPROVED`, `EXPIRED`, `REVOKED`,
and `SUPERSEDED`. Do not create an approved baseline merely because a manifest
can be evaluated; approval must be an external, traceable decision.

#### 7. Classify drift by security impact

Use stable finding IDs that include the affected resource and field, retain
before/after values safely, and distinguish:

- security-critical drift requiring block or rollback
- operational drift requiring review
- benign normalization or ordering changes
- observation uncertainty or unavailable cluster data

Define freshness intervals and alert routing. A drift check that cannot reach
the target should be `UNKNOWN` or `ERROR`, not “no drift”.

#### 8. Cover Kubernetes scope deliberately

Document supported kinds and limitations, then add tests for the intended
scope: Deployments, StatefulSets, DaemonSets, Jobs/CronJobs, Services,
Ingresses, ConfigMaps, Secret references, namespaces, and multiple containers.
Validate multi-document manifests, overlays/rendered output, namespace
selection, init/ephemeral containers, and admission-defaulted fields.

### P1 — Harden the local API and dashboard

The dashboard is useful as a local workbench, but the standard-library HTTP
server must not be presented as a production management plane without
additional controls.

Add or document:

- bind-to-loopback as the safe default and an explicit warning for non-local
  binding
- authentication and authorization supplied by the deployment platform, or
  a clear “local-only, untrusted-network” contract
- restricted CORS instead of `*` when the API is exposed
- request body size limits, timeouts, and concurrency limits
- strict JSON/schema validation with a 4xx response for malformed input
- structured security/audit logging without manifest or secret leakage
- safe path containment checks and filename validation
- HTTPS or a reverse-proxy/TLS deployment contract for remote use
- CSRF protection if browser credentials are ever introduced
- tests for traversal, malformed JSON, oversized bodies, and error handling

This does not require SecureGate to implement identity. It requires SecureGate
to integrate with the hosting platform's identity boundary or remain
explicitly local-only.

### P2 — Prove effectiveness and operability

#### 9. Add security-focused quality gates

Add tests and CI checks for:

- unit, integration, and end-to-end policy decisions
- negative tests for every BLOCK rule
- malformed/truncated/incorrect-version scan reports
- policy exception and threshold behavior
- deterministic report output and schema compatibility
- baseline tampering and invalid baseline files
- path traversal and API abuse cases
- supported Kubernetes version fixtures
- coverage threshold and mutation testing for policy logic

Run static type checking, linting, dependency audit, secret scanning, and
container/image checks in CI. These are pipeline controls around SecureGate,
not new product features that duplicate the existing SAT project.

#### 10. Make Jenkins release behavior explicit

Replace implicit “current build is successful” behavior with explicit stage
dependencies and verified outcomes. Recommended order:

1. checkout and provenance capture
2. build by immutable build ID
3. scan and validate scan evidence
4. render and inspect deployment manifests
5. evaluate policy and publish the evidence bundle
6. push by digest
7. deploy the same digest
8. verify rollout and observed posture
9. record or update a separately approved baseline

Add retention, access controls, artifact integrity, secret masking, and
cleanup policies to Jenkins. Never publish credentials or raw secret values in
reports.

#### 11. Define service-level metrics

Track at least:

- percentage of deployments with a complete evidence bundle
- gate availability and error rate
- time from drift detection to triage
- number and age of active exceptions
- baseline age and expiry compliance
- assessed-digest/deployed-digest mismatches
- false-positive and false-negative findings from reviewed cases
- percentage of supported workload kinds covered by tests

Set owners and targets for each metric. A dashboard without thresholds,
history, and response ownership is visibility, not assurance.

## Suggested delivery sequence

1. Correct documentation and define the report/policy schemas.
2. Implement fail-closed outcomes and immutable evidence bundles.
3. Bind image and manifest digests across Jenkins, registry, and deployment.
4. Add policy/exception governance and baseline approval lifecycle.
5. Add actual-cluster observation and drift freshness handling.
6. Harden the local API or explicitly constrain it to loopback use.
7. Expand Kubernetes fixtures and negative/security regression tests.
8. Add CI quality gates, metrics, retention, and an operational runbook.

## Definition of “defensible”

SecureGate can reasonably be described as defensible when an independent
reviewer can answer “yes” to all of the following:

- Can we prove exactly which source, image digest, manifest, policy, and tool
  versions produced this decision?
- Does any missing, stale, malformed, or unverifiable input fail closed?
- Can we prove that the deployed workload is the one that was assessed?
- Is every exception approved, time-bounded, owned, and visible?
- Can we detect and classify changes to actual deployed posture?
- Can we distinguish policy BLOCK, control ERROR, and unavailable observation?
- Are the supported Kubernetes scope and known limitations documented?
- Can an operator reproduce the decision from retained evidence?
- Are the API and stored reports protected against the intended deployment
  threat model?
- Are upstream SAT and identity results integrated by contract without
  duplicating their responsibilities?

Until these questions are answered with tests and retained evidence, SecureGate
should be presented as a strong deployment-assurance MVP rather than a
complete enterprise DevSecOps control.
