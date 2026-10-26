from .models import PolicyDecision


class Reporter:

    @staticmethod
    def print_report(
        decision: PolicyDecision,
        analyzer,
        risk=None,
    ):
        all_findings = analyzer.all_findings()
        vulnerability_only = bool(all_findings) and all(
            finding.category == "vulnerability"
            for finding in all_findings
        )

        print()
        print("=" * 60)
        print("                    SECUREGATE")
        print("=" * 60)

        print()
        print("SCAN SUMMARY")
        print("-" * 60)

        counts = analyzer.severity_counts()

        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN"
        ]:
            print(
                f"{severity:<10}: {counts.get(severity, 0)}"
            )

        print(
            f"{'TOTAL':<10}: {analyzer.total()}"
        )

        print(
            f"{'FIXABLE':<10}: {analyzer.fixable_count()}"
        )

        print()
        print("POLICY RESULT")
        print("-" * 60)

        print(
            f"{'Blocking vulnerabilities' if vulnerability_only else 'Blocking findings':<25}: "
            f"{len(decision.blocking)}"
        )

        print(
            f"Warnings                 : "
            f"{len(decision.warnings)}"
        )

        print(
            f"Ignored                  : "
            f"{len(decision.ignored)}"
        )

        if decision.blocking:
            print()
            print(
                "BLOCKING VULNERABILITIES"
                if vulnerability_only
                else "BLOCKING FINDINGS"
            )
            print("-" * 60)

            for finding in decision.blocking:
                fixed = (
                    finding.fixed_version
                    or "No fix available"
                )

                if finding.category == "vulnerability":
                    print(
                        f"{finding.vulnerability_id:<18} "
                        f"{finding.severity:<8} "
                        f"{finding.package:<20} "
                        f"Fix: {fixed}"
                    )
                else:
                    print(
                        f"{finding.id:<28} "
                        f"{finding.severity:<8} "
                        f"{finding.resource} - "
                        f"{finding.message}"
                    )

        if decision.warnings:
            print()
            print("WARNINGS")
            print("-" * 60)

            for finding in decision.warnings:
                if finding.category == "vulnerability":
                    print(
                        f"{finding.vulnerability_id:<18} "
                        f"{finding.severity:<8} "
                        f"{finding.package}"
                    )
                else:
                    print(
                        f"{finding.id:<28} "
                        f"{finding.severity:<8} "
                        f"{finding.resource} - "
                        f"{finding.message}"
                    )

        if risk:
            print()
            print("RISK ASSESSMENT")
            print("-" * 60)
            print(
                f"{'Artifact Risk':<20}: {risk.artifact_risk}"
            )
            print(
                f"{'Deployment Risk':<20}: {risk.deployment_risk}"
            )
            print(
                f"{'Drift Risk':<20}: {risk.drift_risk}"
            )
            print(
                f"{'Total Risk':<20}: {risk.total_risk}/100"
            )
            print(
                f"{'Risk Level':<20}: {risk.level}"
            )

        print()
        print("=" * 60)
        print(
            f"SECURITY DECISION: {decision.decision}"
        )
        print("=" * 60)
        print()
