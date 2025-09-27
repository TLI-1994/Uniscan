import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def run_cli(target: Path, *args: str) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "uniscan.main", str(target), *args]
    env = os.environ.copy()
    env.setdefault("UNISCAN_DISABLE_SEMGREP", "1")
    return subprocess.run(command, capture_output=True, text=True, env=env)


@pytest.mark.integration
def test_clean_project_json_output(unity_project):
    target = unity_project("clean_project")
    result = run_cli(target, "--format", "json", "--no-colors")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    assert payload["target"].endswith("clean_project")
    assert payload["summary"]["findings"]["total"] == 0
    assert payload["engine"]["name"] == "heuristic"
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

    assert payload["engine"]["name"] == "heuristic"
    assert "core.unity.proc.exec.process-start" in rule_ids
    severity_counts = payload["summary"]["findings"]
    assert severity_counts["error"] >= 1


@pytest.mark.integration
def test_binary_detection_respects_toggle(unity_project):
    target = unity_project("binary_project")

    with_binaries = run_cli(target, "--format", "json", "--no-colors")
    assert with_binaries.returncode == 0, with_binaries.stderr
    payload = json.loads(with_binaries.stdout)
    assert payload["engine"]["name"] == "heuristic"
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
    assert payload["engine"]["name"] == "heuristic"
    assert payload["binaries"] == []
    assert payload["summary"]["binaries"] == 0


@pytest.mark.integration
def test_cli_errors_on_missing_target(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = run_cli(missing, "--format", "json")

    assert result.returncode == 3
    assert "not found" in result.stderr.lower()


@pytest.mark.integration
def test_pretty_output_groups_findings(unity_project):
    target = unity_project("risky_project")
    result = run_cli(target, "--format", "text", "--pretty", "--no-colors")

    assert result.returncode == 0, result.stderr
    output = result.stdout.splitlines()

    # Expect a file header and a single rule line for process-start
    file_lines = [line for line in output if line.endswith("UnsafeBehaviour.cs")]
    assert file_lines, output
    rule_lines = [line for line in output if "core.unity.proc.exec.process-start" in line]
    assert len(rule_lines) == 1
    # line summary should mention lines
    assert "lines" in rule_lines[0]
