from pathlib import Path

import pytest

from uniscan.semgrep_runner import SemgrepRunner, SemgrepUnavailable


@pytest.mark.integration
def test_semgrep_rules_ignore_comment_only_matches(tmp_path):
    fixtures_dir = Path("tests/fixtures/semgrep_comment_ignore/comment_rules")
    rule_paths = sorted(path.resolve() for path in fixtures_dir.glob("*.yaml"))
    assert rule_paths, "expected comment rule fixtures"

    runner = SemgrepRunner.maybe_create(rule_paths)
    if runner is None:  # pragma: no cover - semgrep binary required
        pytest.skip("semgrep binary not available")

    project = tmp_path / "proj"
    project.mkdir()
    fixture = Path("tests/fixtures/semgrep_comment_ignore/comment_only.cs")
    target = project / "Commented.cs"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    try:
        matches = runner.run(project, [target])
    except SemgrepUnavailable as exc:  # pragma: no cover - depends on system configuration
        pytest.skip(f"semgrep unavailable: {exc}")
    assert matches == []
