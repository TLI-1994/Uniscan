from pathlib import Path

import pytest

from usentinel.semgrep_runner import SemgrepRunner, SemgrepUnavailable


FIXTURE_RULE_DIR = Path("tests/fixtures/semgrep_comment_ignore/comment_rules")


def _load_rule_paths() -> list[Path]:
    rule_paths = sorted(path.resolve() for path in FIXTURE_RULE_DIR.glob("*.yaml"))
    assert rule_paths, "expected comment rule fixtures"
    return rule_paths


def _run_semgrep(rule_paths: list[Path], project_root: Path, target: Path):
    runner = SemgrepRunner.maybe_create(rule_paths)
    if runner is None:  # pragma: no cover - semgrep binary required
        pytest.skip("semgrep binary not available")

    try:
        return runner.run(project_root, [target])
    except SemgrepUnavailable as exc:  # pragma: no cover - depends on system configuration
        pytest.skip(f"semgrep unavailable: {exc}")


@pytest.mark.integration
def test_semgrep_rules_ignore_comment_only_matches(tmp_path):
    rule_paths = _load_rule_paths()

    project = tmp_path / "proj"
    project.mkdir()
    fixture = Path("tests/fixtures/semgrep_comment_ignore/comment_only.cs")
    target = project / "Commented.cs"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    matches = _run_semgrep(rule_paths, project, target)
    assert matches == []


@pytest.mark.integration
def test_semgrep_rules_detect_active_matches(tmp_path):
    rule_paths = _load_rule_paths()

    project = tmp_path / "proj"
    project.mkdir()
    fixture = Path("tests/fixtures/semgrep_comment_ignore/active_matches.cs")
    target = project / "Active.cs"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    matches = _run_semgrep(rule_paths, project, target)

    assert matches, "expected semgrep to report matches"
    rule_ids = {match.rule_id for match in matches}
    assert any(rid.endswith("test.autorun.class") for rid in rule_ids)
    assert any(rid.endswith("test.binary.formatter") for rid in rule_ids)
