from .models import PolicyDecision


class Reporter:

    @staticmethod
    def print_report(
        decision: PolicyDecision,
        analyzer
    ):

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
            f"Blocking vulnerabilities : "
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
            print("BLOCKING VULNERABILITIES")
            print("-" * 60)

            for vulnerability in decision.blocking:
                fixed = (
                    vulnerability.fixed_version
                    or "No fix available"
                )

                print(
                    f"{vulnerability.vulnerability_id:<18} "
                    f"{vulnerability.severity:<8} "
                    f"{vulnerability.package:<20} "
                    f"Fix: {fixed}"
                )

        if decision.warnings:
            print()
            print("WARNINGS")
            print("-" * 60)

            for vulnerability in decision.warnings:
                print(
                    f"{vulnerability.vulnerability_id:<18} "
                    f"{vulnerability.severity:<8} "
                    f"{vulnerability.package}"
                )

        print()
        print("=" * 60)
        print(
            f"SECURITY DECISION: {decision.decision}"
        )
        print("=" * 60)
        print()