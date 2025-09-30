import json
from pathlib import Path
from typing import Sequence

import pytest

import usentinel.scanner as scanner_module
from usentinel.binaries import BinaryClassifier
from usentinel.rules import load_ruleset, load_semgrep_sources
from usentinel.scanner import Scanner, ScannerConfig
from usentinel.semgrep_runner import SemgrepRunner, SemgrepUnavailable


class _FailingRunner:
    def __init__(self, message: str) -> None:
        self.message = message

    def run(self, project_root: Path, targets: Sequence[Path]):
        raise SemgrepUnavailable(self.message)


def test_scanner_records_fallback_reason(monkeypatch, unity_project):
    message = "semgrep exploded"
    monkeypatch.setenv("USENTINEL_DISABLE_SEMGREP", "")

    def fake_runner(_sources, jobs=None):
        return _FailingRunner(message)

    stub = type("Stub", (), {"maybe_create": staticmethod(fake_runner)})
    monkeypatch.setattr(scanner_module, "SemgrepRunner", stub)

    ruleset = load_ruleset(include_private=True)
    semgrep_sources = load_semgrep_sources(include_private=False)
    assert semgrep_sources, "expected at least one semgrep rule source"
    scanner = Scanner(
        ruleset=ruleset,
        semgrep_sources=semgrep_sources,
        binary_classifier=BinaryClassifier(),
        config=ScannerConfig(include_binaries=False, skip_binaries=True),
    )

    report = scanner.scan(unity_project("risky_project"))
    assert report.engine["name"] == "heuristic"
    assert message in str(report.engine.get("fallback_reason"))
    assert any(f.rule_id == "core.unity.proc.exec.process-start" for f in report.findings)


def test_semgrep_runner_builds_command(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, capture_output, text, cwd, env, check):  # noqa: D417
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["env"] = env
        return type("Result", (), {"returncode": 0, "stdout": json.dumps({"results": []})})()

    monkeypatch.setattr("subprocess.run", fake_run)

    rule = tmp_path / "rules.yaml"
    rule.write_text("rules: []")

    runner = SemgrepRunner("semgrep", [rule], jobs=8)
    project = tmp_path / "proj"
    project.mkdir()
    target = project / "file.cs"
    target.write_text("class Foo {}")
    target2 = project / "file2.cs"
    target2.write_text("class Bar {}")

    matches = runner.run(project, [target, target2])

    assert matches == []
    assert captured["cmd"][0] == "semgrep"
    assert "--config" in captured["cmd"]
    assert str(rule) in captured["cmd"]
    assert captured["cwd"] == str(project)
    assert captured["env"].get("SEMGREP_SEND_METRICS") == "off"
    assert "--jobs" in captured["cmd"]
