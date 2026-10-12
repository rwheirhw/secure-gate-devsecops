# SecureGate Core Package

This package contains the core components of SecureGate:

- `models.py`: Core data structures (`Finding`, `ScanResult`, `PolicyDecision`, `RiskAssessment`, `SecurityBaseline`, `DriftEvent`).
- `scanners/`: Container vulnerability scanning adapters (Trivy scanner).
- `inspectors/`: Kubernetes deployment inspection with in-memory and file-based loaders (`KubernetesInspector`).
- `analyzers/`: Specialized analyzers (`VulnerabilityAnalyzer`, `DeploymentAnalyzer`, and backward-compatible `Analyzer`).
- `policy/`: Policy engine supporting both YAML (`config/policy.yaml`) and JSON (`config/policy.json`).
- `risk.py`: Transparent posture risk scoring engine.
- `baseline.py`: Baseline storage and drift detection engine.
- `server.py`: REST API and Web Dashboard HTTP server.
- `web/`: Modern glassmorphic web dashboard frontend (`index.html`, `style.css`, `app.js`).
- `cli.py`: Command-line interface with `assess`, `inspect`, `baseline`, `drift`, and `serve` commands.

Refer to the root [README.md](file:///c:/Users/chara/SecureGate/README.md) for full documentation.
