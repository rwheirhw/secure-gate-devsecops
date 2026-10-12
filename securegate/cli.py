from pathlib import Path

import typer

from .analyzer import Analyzer
from .baseline import BaselineStore, DriftDetector
from .inspectors.kubernetes import KubernetesInspector
from .json_reporter import JsonReporter
from .models import ScanResult
from .parser import TrivyParser
from .policy import PolicyEngine
from .reporter import Reporter
from .risk import RiskEngine
from .scanners.trivy import TrivyScanner


app = typer.Typer(
    name="securegate",
    help="DevSecOps deployment security assurance system.",
)


@app.command()
def evaluate(
    report: Path = typer.Argument(
        ...,
        help="Path to a Trivy JSON report.",
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy.",
    ),
    json_output: Path = typer.Option(
        None,
        "--json-output",
        "-j",
        help="Write structured JSON report to this path.",
    ),
):
    """Evaluate an existing Trivy JSON report."""

    try:
        parser = TrivyParser(str(report))
        scan_results = parser.parse()

        analyzer = Analyzer(scan_results)

        policy_engine = PolicyEngine(str(policy))

        decision = policy_engine.evaluate(
            analyzer.all_findings()
        )
        risk = RiskEngine().assess(
            analyzer.all_findings()
        )

        Reporter.print_report(
            decision,
            analyzer,
            risk,
        )

        if json_output:
            json_report = JsonReporter.generate(
                decision,
                analyzer,
                risk,
                metadata={"report": str(report)},
            )
            path = JsonReporter.write(
                json_report,
                str(json_output),
            )
            typer.echo(
                f"JSON report written: {path}"
            )

        raise typer.Exit(
            code=1 if decision.decision == "BLOCK" else 0
        )

    except typer.Exit:
        raise

    except Exception as exc:
        typer.echo(
            f"SecureGate ERROR: {exc}",
            err=True,
        )
        raise typer.Exit(code=2)


@app.command()
def scan(
    image: str = typer.Argument(
        ...,
        help="Container image to scan."
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy."
    ),
    output: Path = typer.Option(
        Path("reports/scan.json"),
        "--output",
        "-o",
        help="Where to save the Trivy JSON report."
    ),
):
    """Scan a container image and evaluate its security policy."""

    try:
        typer.echo(
            f"Scanning image: {image}"
        )

        scanner = TrivyScanner()

        report_path = scanner.scan(
            image=image,
            output_path=str(output)
        )

        typer.echo(
            f"Trivy report: {report_path}"
        )

        parser = TrivyParser(
            str(report_path)
        )

        scan_results = parser.parse()

        analyzer = Analyzer(
            scan_results
        )

        policy_engine = PolicyEngine(
            str(policy)
        )

        decision = policy_engine.evaluate(
            analyzer.all_findings()
        )
        risk = RiskEngine().assess(
            analyzer.all_findings()
        )

        Reporter.print_report(
            decision,
            analyzer,
            risk,
        )

        raise typer.Exit(
            code=1 if decision.decision == "BLOCK" else 0
        )

    except typer.Exit:
        raise

    except Exception as exc:
        typer.echo(
            f"SecureGate ERROR: {exc}",
            err=True
        )
        raise typer.Exit(code=2)


@app.command()
def inspect(
    manifest: Path = typer.Argument(
        ...,
        help="Path to a Kubernetes manifest file or directory.",
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy.",
    ),
    json_output: Path = typer.Option(
        None,
        "--json-output",
        "-j",
        help="Write structured JSON report to this path.",
    ),
):
    """Inspect Kubernetes deployment configuration and evaluate policy."""

    try:
        inspector = KubernetesInspector(
            str(manifest)
        )
        findings = inspector.inspect()

        analyzer = Analyzer(
            [
                ScanResult(
                    target=str(manifest),
                    findings=findings,
                )
            ]
        )

        policy_engine = PolicyEngine(
            str(policy)
        )

        decision = policy_engine.evaluate(
            analyzer.all_findings()
        )
        risk = RiskEngine().assess(
            analyzer.all_findings()
        )

        Reporter.print_report(
            decision,
            analyzer,
            risk,
        )

        if json_output:
            json_report = JsonReporter.generate(
                decision,
                analyzer,
                risk,
                metadata={"manifest": str(manifest)},
            )
            path = JsonReporter.write(
                json_report,
                str(json_output),
            )
            typer.echo(
                f"JSON report written: {path}"
            )

        raise typer.Exit(
            code=1 if decision.decision == "BLOCK" else 0
        )

    except typer.Exit:
        raise

    except Exception as exc:
        typer.echo(
            f"SecureGate ERROR: {exc}",
            err=True,
        )
        raise typer.Exit(code=2)


@app.command()
def baseline(
    manifest: Path = typer.Argument(
        ...,
        help="Path to an approved Kubernetes manifest file or directory."
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy."
    ),
    output: Path = typer.Option(
        Path("baselines/security-baseline.json"),
        "--output",
        "-o",
        help="Where to write the approved security baseline."
    ),
):
    """Create an approved security baseline for a passing manifest."""

    try:
        inspector = KubernetesInspector(
            str(manifest)
        )
        findings = inspector.inspect()

        analyzer = Analyzer(
            [
                ScanResult(
                    target=str(manifest),
                    findings=findings,
                )
            ]
        )

        policy_engine = PolicyEngine(
            str(policy)
        )
        decision = policy_engine.evaluate(
            analyzer.all_findings()
        )
        risk = RiskEngine().assess(
            analyzer.all_findings()
        )

        Reporter.print_report(
            decision,
            analyzer,
            risk,
        )

        if decision.decision == "BLOCK":
            typer.echo(
                "SecureGate baseline was not written because policy "
                "decision is BLOCK.",
                err=True,
            )
            raise typer.Exit(code=1)

        baseline_path = BaselineStore().save(
            output_path=str(output),
            manifest=str(manifest),
            posture=inspector.posture(),
            risk=risk,
        )

        typer.echo(
            f"Approved security baseline written: {baseline_path}"
        )
        raise typer.Exit(code=0)

    except typer.Exit:
        raise

    except Exception as exc:
        typer.echo(
            f"SecureGate ERROR: {exc}",
            err=True
        )
        raise typer.Exit(code=2)


@app.command()
def drift(
    baseline_file: Path = typer.Argument(
        ...,
        help="Path to an approved SecureGate baseline JSON file."
    ),
    manifest: Path = typer.Argument(
        ...,
        help="Path to the current Kubernetes manifest file or directory."
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy."
    ),
):
    """Detect security-posture drift against an approved baseline."""

    try:
        store = BaselineStore()
        approved = store.load(
            str(baseline_file)
        )
        inspector = KubernetesInspector(
            str(manifest)
        )
        current_posture = inspector.posture()
        detector = DriftDetector()
        drift_events = detector.detect(
            approved["posture"],
            current_posture,
        )
        findings = detector.findings_for(
            drift_events
        )

        analyzer = Analyzer(
            [
                ScanResult(
                    target=str(manifest),
                    findings=findings,
                )
            ]
        )

        policy_engine = PolicyEngine(
            str(policy)
        )
        decision = policy_engine.evaluate(
            analyzer.all_findings()
        )
        risk = RiskEngine().assess(
            analyzer.all_findings()
        )

        Reporter.print_report(
            decision,
            analyzer,
            risk,
        )

        raise typer.Exit(
            code=1 if decision.decision == "BLOCK" else 0
        )

    except typer.Exit:
        raise

    except Exception as exc:
        typer.echo(
            f"SecureGate ERROR: {exc}",
            err=True
        )
        raise typer.Exit(code=2)


@app.command()
def assess(
    report: Path = typer.Argument(
        ...,
        help="Path to a Trivy JSON report.",
    ),
    manifest: Path = typer.Argument(
        ...,
        help="Path to a Kubernetes manifest file or directory.",
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy.",
    ),
    json_output: Path = typer.Option(
        None,
        "--json-output",
        "-j",
        help="Write structured JSON report to this path.",
    ),
):
    """Combined assessment: evaluate Trivy findings AND K8s manifest together."""

    try:
        # --- Artifact security (Trivy) ---
        parser = TrivyParser(str(report))
        trivy_results = parser.parse()

        # --- Deployment security (K8s) ---
        inspector = KubernetesInspector(
            str(manifest)
        )
        k8s_findings = inspector.inspect()

        # Merge both sources into a single analysis.
        all_results = list(trivy_results) + [
            ScanResult(
                target=str(manifest),
                findings=k8s_findings,
            )
        ]

        analyzer = Analyzer(all_results)

        policy_engine = PolicyEngine(
            str(policy)
        )
        decision = policy_engine.evaluate(
            analyzer.all_findings()
        )
        risk = RiskEngine().assess(
            analyzer.all_findings()
        )

        Reporter.print_report(
            decision,
            analyzer,
            risk,
        )

        if json_output:
            json_report = JsonReporter.generate(
                decision,
                analyzer,
                risk,
                metadata={
                    "report": str(report),
                    "manifest": str(manifest),
                    "mode": "combined",
                },
            )
            path = JsonReporter.write(
                json_report,
                str(json_output),
            )
            typer.echo(
                f"JSON report written: {path}"
            )

        raise typer.Exit(
            code=1 if decision.decision == "BLOCK" else 0
        )

    except typer.Exit:
        raise

    except Exception as exc:
        typer.echo(
            f"SecureGate ERROR: {exc}",
            err=True,
        )
        raise typer.Exit(code=2)


@app.command()
def version():
    """Display SecureGate version."""

    typer.echo("SecureGate 0.2.0")


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-h",
        help="Host address to bind the web dashboard and API server.",
    ),
    port: int = typer.Option(
        8088,
        "--port",
        "-p",
        help="Port number to run the web dashboard and API server.",
    ),
):
    """Run the SecureGate Web Dashboard and REST API server."""
    from .server import run_server

    run_server(host=host, port=port)


if __name__ == "__main__":
    app()
