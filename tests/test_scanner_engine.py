from uniscan.binaries import BinaryClassifier
from uniscan.rules import load_ruleset
from uniscan.scanner import ScanReport, Scanner, ScannerConfig


def make_scanner(include_binaries: bool = True) -> Scanner:
    ruleset = load_ruleset(include_private=True)
    classifier = BinaryClassifier()
    config = ScannerConfig(include_binaries=include_binaries, skip_binaries=not include_binaries)
    return Scanner(ruleset=ruleset, binary_classifier=classifier, config=config)


def test_scanner_reports_no_findings_for_clean_project(unity_project):
    scanner = make_scanner()
    report = scanner.scan(unity_project("clean_project"))

    assert isinstance(report, ScanReport)
    assert report.summary["findings"]["total"] == 0
    assert report.findings == []


def test_scanner_flags_process_start(unity_project):
    scanner = make_scanner()
    report = scanner.scan(unity_project("risky_project"))

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "unity.proc.exec.process-start" in rule_ids


def test_scanner_can_skip_binaries(unity_project):
    scanner = make_scanner(include_binaries=False)
    report = scanner.scan(unity_project("binary_project"))

    assert report.binaries == []
    assert report.summary["binaries"] == 0
