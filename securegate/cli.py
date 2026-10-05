from pathlib import Path

import typer

from .analyzer import Analyzer
from .parser import TrivyParser
from .policy import PolicyEngine
from .reporter import Reporter
from .scanner import TrivyScanner


app = typer.Typer(
    name="securegate",
    help="Container vulnerability security gate."
)


@app.command()
def evaluate(
    report: Path = typer.Argument(
        ...,
        help="Path to a Trivy JSON report."
    ),
    policy: Path = typer.Option(
        Path("config/policy.json"),
        "--policy",
        "-p",
        help="Path to SecureGate policy."
    ),
):
    """Evaluate an existing Trivy JSON report."""

    try:
        parser = TrivyParser(str(report))
        scan_results = parser.parse()

        analyzer = Analyzer(scan_results)

        policy_engine = PolicyEngine(str(policy))

        decision = policy_engine.evaluate(
            analyzer.all_vulnerabilities()
        )

        Reporter.print_report(
            decision,
            analyzer
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
            analyzer.all_vulnerabilities()
        )

        Reporter.print_report(
            decision,
            analyzer
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
def version():
    """Display SecureGate version."""

    typer.echo("SecureGate 0.1.0")


if __name__ == "__main__":
    app()