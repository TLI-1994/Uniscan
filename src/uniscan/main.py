from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .binaries import BinaryClassifier
from .cli import CliOptions, parse_args
from .rules import RuleLoadError, load_ruleset
from .scanner import Finding, ScanReport, Scanner, ScannerConfig

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FS_ERROR = 3
EXIT_RULE_ERROR = 4
EXIT_FAILURE = 1

_RESET = "\x1b[0m"
_COLORS = {
    "info": "\x1b[34m",  # blue
    "warning": "\x1b[33m",  # yellow
    "error": "\x1b[31m",  # red
    "critical": "\x1b[35m",  # magenta
}


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
        use_semgrep=_map_engine_choice(options.semgrep),
        show_progress=options.progress,
    )

    scanner = Scanner(ruleset=ruleset, binary_classifier=classifier, config=config)
    return scanner.scan(options.target)


def _map_engine_choice(choice: str) -> bool | None:
    if choice == "semgrep":
        return True
    if choice == "heuristic":
        return False
    return None


def _report_to_json(report: ScanReport, options: CliOptions) -> str:
    payload: dict[str, Any] = {
        "target": str(report.target),
        "summary": report.summary,
        "engine": report.engine,
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
    engine_name = str(report.engine.get("name", "unknown"))
    fallback = report.engine.get("fallback_reason")
    if fallback:
        fallback_str = str(fallback)
        lines.append(f"Analysis engine: {engine_name} (fallback: {fallback_str})")
    else:
        lines.append(f"Analysis engine: {engine_name}")

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

    lines.extend(_format_findings_text(report.findings, options))

    return "\n".join(lines)


def _format_findings_text(findings: Sequence[Finding], options: CliOptions) -> list[str]:
    if options.verbosity == "quiet":
        return []

    colorize = not options.no_colors
    lines: list[str] = []
    for finding in findings:
        rule_display = finding.rule_id
        severity = finding.severity.upper()
        location = f"{finding.path}:{finding.line}" if finding.line else str(finding.path)
        snippet = f" \u2014 {finding.snippet}" if options.verbosity == "debug" and finding.snippet else ""

        severity_text = severity
        if colorize:
            color = _severity_color(finding.severity)
            if color:
                rule_display = f"{color}{rule_display}{_RESET}"
                severity_text = f"{color}{severity}{_RESET}"

        lines.append(f"[{rule_display}] {severity_text} - {finding.message} ({location}){snippet}")

    return lines


def _severity_color(severity: str) -> str | None:
    return _COLORS.get(severity.lower())


def _print_error(message: str) -> None:
    print(message, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
