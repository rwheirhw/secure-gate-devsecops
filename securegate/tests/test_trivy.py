import subprocess

import pytest

from securegate.scanner import TrivyScanner as LegacyTrivyScanner
from securegate.scanners.trivy import TrivyScanner


def test_trivy_scanner_runs_expected_command(monkeypatch, tmp_path):
    output_path = tmp_path / "reports" / "scan.json"
    calls = []

    def fake_run(command, capture_output, text, check):
        calls.append(
            {
                "command": command,
                "capture_output": capture_output,
                "text": text,
                "check": check,
            }
        )
        output_path.write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "securegate.scanners.trivy.subprocess.run",
        fake_run,
    )

    result = TrivyScanner(
        trivy_path="custom-trivy"
    ).scan(
        image="alpine:latest",
        output_path=str(output_path),
    )

    assert result == output_path
    assert calls == [
        {
            "command": [
                "custom-trivy",
                "image",
                "--format",
                "json",
                "--output",
                str(output_path),
                "alpine:latest",
            ],
            "capture_output": True,
            "text": True,
            "check": False,
        }
    ]


def test_legacy_scanner_import_path_still_exports_trivy_scanner():
    assert LegacyTrivyScanner is TrivyScanner


def test_trivy_scanner_raises_when_report_is_missing(monkeypatch, tmp_path):
    output_path = tmp_path / "missing.json"

    def fake_run(command, capture_output, text, check):
        return subprocess.CompletedProcess(
            command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "securegate.scanners.trivy.subprocess.run",
        fake_run,
    )

    with pytest.raises(RuntimeError, match="no report was created"):
        TrivyScanner().scan(
            image="alpine:latest",
            output_path=str(output_path),
        )
