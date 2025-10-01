import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest


def run_cli(target: Path, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "usentinel.main", str(target), *args]
    env = os.environ.copy()
    env.setdefault("USENTINEL_DISABLE_SEMGREP", "1")
    src_path = Path(__file__).resolve().parent.parent / "src"
    existing_pythonpath = env.get("PYTHONPATH")
    if existing_pythonpath:
        env["PYTHONPATH"] = os.pathsep.join([str(src_path), existing_pythonpath])
    else:
        env["PYTHONPATH"] = str(src_path)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
    )


@pytest.mark.integration
def test_clean_project_json_output(unity_project):
    target = unity_project("clean_project")
    result = run_cli(target, "--format", "raw")

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
    result = run_cli(target, "--format", "raw")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)

    findings = payload["findings"]
    rule_ids = {finding["rule_id"] for finding in findings}

    assert payload["engine"]["name"] == "heuristic"
    assert "core.unity.proc.exec.process-start" in rule_ids
    severity_counts = payload["summary"]["findings"]
    assert severity_counts["high"] >= 1


@pytest.mark.integration
def test_binary_detection_respects_toggle(unity_project):
    target = unity_project("binary_project")

    with_binaries = run_cli(target, "--format", "raw")
    assert with_binaries.returncode == 0, with_binaries.stderr
    payload = json.loads(with_binaries.stdout)
    assert payload["engine"]["name"] == "heuristic"
    assert payload["binaries"] != []
    paths = {entry["path"] for entry in payload["binaries"]}
    assert any(path.endswith("native.dll") for path in paths)

    without_binaries = run_cli(
        target,
        "--format",
        "raw",
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
    result = run_cli(missing, "--format", "raw")

    assert result.returncode == 3
    assert "not found" in result.stderr.lower()


@pytest.mark.integration
def test_html_format_writes_report(unity_project, tmp_path):
    target = unity_project("risky_project")
    output_path = tmp_path / "report.html"

    result = run_cli(
        target,
        "--format",
        "html",
        "--output",
        str(output_path),
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    assert output_path.exists()
    assert "HTML report written" in result.stdout
    assert str(output_path) in result.stdout
    html = output_path.read_text(encoding="utf-8")
    assert "Usentinel Scan Report" in html
    assert "Findings" in html


@pytest.mark.integration
def test_html_format_does_not_overwrite_existing_file(unity_project, tmp_path):
    target = unity_project("risky_project")
    existing = tmp_path / "report.html"
    existing.write_text("old", encoding="utf-8")

    result = run_cli(
        target,
        "--format",
        "html",
        "--output",
        str(existing),
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    assert existing.read_text(encoding="utf-8") == "old"
    fallback = tmp_path / "report-1.html"
    assert fallback.exists()
    assert str(fallback) in result.stdout


@pytest.mark.integration
def test_html_format_generates_timestamped_name(unity_project, tmp_path):
    target = unity_project("risky_project")

    result = run_cli(
        target,
        "--format",
        "html",
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr

    html_files = list(tmp_path.glob("usentinel-report-*.html"))
    assert len(html_files) == 1
    generated = html_files[0]
    pattern = re.compile(
        r"usentinel-report-risky-project-\d{8}-\d{6}-[0-9a-f]{8}\.html"
    )
    assert pattern.fullmatch(generated.name)
    assert str(generated) in result.stdout
