# Changelog

## 0.3.1 - 2025-10-02
### Semgrep Integration
- Require Semgrep >=1.132.0 on Windows to pick up official CLI builds and document snippet login requirements for those users.

## 0.3.0 - 2025-10-02
### Highlights
- Added a first-class HTML reporting pipeline with templated layout, severity summaries, expandable snippets, and embedded Usentinel/Semgrep metadata so teams can review findings in a shareable format.
- Bundled syntax highlighting via Pygments and packaged HTML assets, producing polished reports with light/dark mode support and deterministic filenames.

### CLI & UX
- Simplified output selection to `html` or `raw` (`json` still accepted) and auto-detect interactive terminals to decide when to show progress bars and spinners.
- Defaulted scans to HTML output, writing reports to unique paths (or a user-specified directory/file) and printing the result location.

### Semgrep Integration
- Surface the detected Semgrep version in scan metadata and constrain supported releases to the vetted `>=1.72,<=1.97` range.
- Hardened the Semgrep invocation environment to skip telemetry/update checks consistently.

### Documentation
- Refreshed the README to describe HTML report generation, clarify binary/output behavior, and refine contributor testing guidance and badge layout.

## 0.2.0 - 2024-09-29
### Highlights
- Rebranded the project from Uniscan to Usentinel, including package, CLI command, and documentation updates.
- Normalized severity handling to Semgrep’s Critical/High/Medium/Low scale and sorted findings by severity in both text and pretty output modes.

### Packaging & Meta
- Prepared PyPI metadata for `usentinel`, including updated rule bundle namespace.
- Added environment variable fallbacks (`USENTINEL_DISABLE_SEMGREP`, `USENTINEL_SEMGREP_BINARY`) while retaining backward compatibility with the previous names.

## 0.1.1 - 2024-09-29
### Highlights
- Added `-V/--version` flag to report the installed Uniscan version.
- Clarified CLI flag defaults and documented Semgrep snippet behavior.
- Overhauled README with PyPI badge, installation guidance, and expanded disclaimer.

### Packaging & Meta
- Converted the README license link to an absolute URL so it renders correctly on PyPI.
- Strengthened the README legal disclaimer and encouraged community contributions for rule coverage.

## 0.1.0 - 2024-09-28
### Highlights
- 🎉 First public release of Uniscan — a lightweight security scanner for Unity projects.
- Dual engines: fast heuristic analysis and Semgrep-based scanning, selectable via `--engine`.
- Clear, per-rule reporting with optional grouped output and progress indicators enabled by default.

### Rule Coverage
- Ships with a curated Unity rule bundle covering risky reflection, serialization, crypto, and network patterns.
- Rules are versioned with the package, reproducible from structured specs, and tested to ensure AST patterns match code (not comments).

### CLI & UX
- Progress spinner and elapsed-time display during long Semgrep runs, with streamlined engine announcements.
- Added `--pretty` flag for grouped findings, consistent rule IDs (`core.*`) and normalized output across engines.
- Better environment diagnostics (scan engine selection, binary inclusion) and sensible defaults (`--progress` on).

### Packaging & Automation
- Publishable PyPI metadata with author info, keywords, and project URLs; markdown README used as the long description.
- Wheel now bundles the Unity rule set for offline installs.
- GitHub Actions workflow runs pytest on Python 3.10–3.12, builds release artifacts, and archives `dist/` output for review.
