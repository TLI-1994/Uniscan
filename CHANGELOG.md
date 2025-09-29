# Changelog

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
