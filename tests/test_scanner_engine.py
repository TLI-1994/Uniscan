from usentinel.binaries import BinaryClassifier
from usentinel.rules import load_ruleset
from usentinel.scanner import ScanReport, Scanner, ScannerConfig


def make_scanner(include_binaries: bool = True) -> Scanner:
    ruleset = load_ruleset(include_private=True)
    classifier = BinaryClassifier()
    config = ScannerConfig(
        include_binaries=include_binaries,
        skip_binaries=not include_binaries,
        use_semgrep=False,
    )
    return Scanner(ruleset=ruleset, semgrep_sources=(), binary_classifier=classifier, config=config)


def test_scanner_reports_no_findings_for_clean_project(unity_project):
    scanner = make_scanner()
    report = scanner.scan(unity_project("clean_project"))

    assert isinstance(report, ScanReport)
    assert report.summary["findings"]["total"] == 0
    assert report.findings == []
    assert report.engine["name"] == "heuristic"


def test_scanner_flags_process_start(unity_project):
    scanner = make_scanner()
    report = scanner.scan(unity_project("risky_project"))

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "core.unity.proc.exec.process-start" in rule_ids
    assert report.engine["name"] == "heuristic"


def test_scanner_can_skip_binaries(unity_project):
    scanner = make_scanner(include_binaries=False)
    report = scanner.scan(unity_project("binary_project"))

    assert report.binaries == []
    assert report.summary["binaries"] == 0
    assert report.engine["name"] == "heuristic"


def test_scanner_reports_multiple_matches_per_rule(unity_project):
    scanner = make_scanner()
    report = scanner.scan(unity_project("multi_match_project"))

    autorun_findings = [
        finding for finding in report.findings if finding.rule_id == "core.unity.autorun.editor-hooks"
    ]

    assert len(autorun_findings) == 2
    assert {finding.line for finding in autorun_findings} == {5, 10}
