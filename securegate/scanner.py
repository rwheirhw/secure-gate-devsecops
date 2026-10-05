import subprocess
from pathlib import Path


class TrivyScanner:
    def __init__(
        self,
        trivy_path: str = "trivy",
    ):
        self.trivy_path = trivy_path

    def scan(
        self,
        image: str,
        output_path: str,
    ) -> Path:

        output = Path(output_path)

        output.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        command = [
            self.trivy_path,
            "image",
            "--format",
            "json",
            "--output",
            str(output),
            image,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

        except FileNotFoundError as exc:
            raise RuntimeError(
                "Trivy executable was not found. "
                "Make sure Trivy is installed and available in PATH."
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(
                "Trivy scan failed.\n"
                f"Exit code: {result.returncode}\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            )

        if not output.exists():
            raise RuntimeError(
                f"Trivy completed successfully, "
                f"but no report was created at: {output}"
            )

        return output