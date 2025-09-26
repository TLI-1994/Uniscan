import json
import subprocess
import sys
from pathlib import Path

import pytest


def run_cli(target: Path, *args: str) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "uniscan.main", str(target), *args]
    return subprocess.run(command, capture_output=True, text=True)


@pytest.mark.integration
def test_clean_project_json_output(unity_project):
    target = unity_project("clean_project")
    result = run_cli(target, "--format", "json", "--no-colors")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    assert payload["target"].endswith("clean_project")
    assert payload["summary"]["findings"]["total"] == 0
    assert payload["findings"] == []
    assert payload["binaries"] == []


@pytest.mark.integration
def test_risky_project_reports_process_start(unity_project):
    target = unity_project("risky_project")
    result = run_cli(target, "--format", "json", "--no-colors")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    findings = payload["findings"]
    rule_ids = {finding["rule_id"] for finding in findings}

    assert "unity.proc.exec.process-start" in rule_ids
    severity_counts = payload["summary"]["findings"]
    assert severity_counts["error"] >= 1


@pytest.mark.integration
def test_binary_detection_respects_toggle(unity_project):
    target = unity_project("binary_project")

    with_binaries = run_cli(target, "--format", "json", "--no-colors")
    assert with_binaries.returncode == 0, with_binaries.stderr
    payload = json.loads(with_binaries.stdout)
    assert payload["binaries"] != []
    paths = {entry["path"] for entry in payload["binaries"]}
    assert any(path.endswith("native.dll") for path in paths)

    without_binaries = run_cli(
        target,
        "--format",
        "json",
        "--no-colors",
        "--skip-binaries",
    )
    assert without_binaries.returncode == 0, without_binaries.stderr
    payload = json.loads(without_binaries.stdout)
    assert payload["binaries"] == []
    assert payload["summary"]["binaries"] == 0


@pytest.mark.integration
def test_cli_errors_on_missing_target(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = run_cli(missing, "--format", "json")

    assert result.returncode == 3
    assert "not found" in result.stderr.lower()
