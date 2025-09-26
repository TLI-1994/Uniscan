from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .binaries import BinaryClassifier
from .cli import CliOptions, parse_args
from .rules import RuleLoadError, load_ruleset
from .scanner import ScanReport, Scanner, ScannerConfig

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FS_ERROR = 3
EXIT_RULE_ERROR = 4
EXIT_FAILURE = 1


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    try:
        options = parse_args(argv)
    except SystemExit as exc:
        # argparse already emitted a message; propagate its exit code
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE

    try:
        report = run_scan(options)
    except FileNotFoundError as exc:
        _print_error(str(exc))
        return EXIT_FS_ERROR
    except NotADirectoryError as exc:
        _print_error(str(exc))
        return EXIT_FS_ERROR
    except RuleLoadError as exc:
        _print_error(str(exc))
        return EXIT_RULE_ERROR
    except Exception as exc:  # pragma: no cover - defensive final guard
        _print_error(f"Unexpected error: {exc}")
        return EXIT_FAILURE

    if options.format == "json":
        print(_report_to_json(report, options))
    else:
        print(_report_to_text(report, options))

    return EXIT_OK


def run_scan(options: CliOptions) -> ScanReport:
    extra_rule_files = options.ruleset if options.ruleset else None
    ruleset = load_ruleset(include_private=True, extra_rule_files=extra_rule_files)

    classifier = BinaryClassifier()
    should_include_binaries = options.include_binaries or not options.skip_binaries
    config = ScannerConfig(
        include_binaries=should_include_binaries,
        skip_binaries=options.skip_binaries,
    )

    scanner = Scanner(ruleset=ruleset, binary_classifier=classifier, config=config)
    return scanner.scan(options.target)


def _report_to_json(report: ScanReport, options: CliOptions) -> str:
    payload: dict[str, Any] = {
        "target": str(report.target),
        "summary": report.summary,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "message": finding.message,
                "path": str(finding.path),
                "line": finding.line,
                "snippet": finding.snippet,
            }
            for finding in report.findings
        ],
        "binaries": [
            {
                "path": str(binary.path),
                "kind": binary.kind,
                "size": binary.size,
                "magic": binary.magic,
            }
            for binary in report.binaries
        ],
    }
    return json.dumps(payload, indent=2 if options.verbosity == "debug" else None)


def _report_to_text(report: ScanReport, options: CliOptions) -> str:
    lines = [f"Scan target: {report.target}"]
    counts = report.summary.get("findings", {})
    lines.append(
        "Findings: total={total} info={info} warning={warning} error={error}".format(
            total=counts.get("total", 0),
            info=counts.get("info", 0),
            warning=counts.get("warning", 0),
            error=counts.get("error", 0),
        )
    )
    if report.summary.get("binaries"):
        lines.append(f"Native binaries detected: {report.summary['binaries']}")

    for finding in report.findings:
        location = f"{finding.path}:{finding.line}" if finding.line else str(finding.path)
        lines.append(f"[{finding.rule_id}] {finding.severity.upper()} - {finding.message} ({location})")

    return "\n".join(lines)


def _print_error(message: str) -> None:
    print(message, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
