# Uniscan

[![PyPI](https://img.shields.io/pypi/v/uniscan.svg?label=PyPI)](https://pypi.org/project/uniscan/)

**Uniscan** is a **lightweight, read-only command-line interface (CLI) tool** designed to **audit Unity projects** for potentially hazardous code and native binaries. It's a quick and simple way to get a security overview of your project without needing a complex setup. The tool scans C# scripts for risky patterns and provides a clear, color-coded summary directly in your terminal.

### Key Features
* **Static Code Analysis:** Scans C# scripts for common security vulnerabilities and anti-patterns.
* **Binary Detection:** Identifies native binary files (e.g., `.dll`, `.so`, `.dylib`) which can sometimes pose a risk.
* **Clear, Color-Coded Output:** Provides an easy-to-read summary of findings, highlighting issues with different colors.
* **Minimalist Design:** It's read-only, has minimal dependencies, and won't modify your project.

---

## Installation & Usage

Install from PyPI:

```bash
pip install uniscan
```

Then scan your Unity project:

```bash
uniscan /path/to/unity/project
```

Want to run from source instead?

```bash
git clone https://github.com/TLI-1994/Uniscan.git
cd Uniscan
PYTHONPATH=src python -m uniscan.main /path/to/unity/project
```

Common flags:

* `--format {text|json}` – choose human-readable or machine-readable output (`text` is default)
* `--no-colors` – disable ANSI colours in text mode
* `--ruleset path/to/extra_rules.yaml` – load additional Semgrep-style YAML rules (may be passed multiple times)
* `--skip-binaries` / `--include-binaries` – control native binary detection
* `--verbosity {quiet|normal|debug}` – adjust the amount of detail printed (aliases `--quiet` and `--debug`)
* `--engine {auto|semgrep|heuristic}` – force Semgrep, always use the lightweight heuristic scanner, or let Uniscan decide automatically
* `--progress` / `--no-progress` – toggle the live progress indicator (enabled by default)
* `--pretty` / `--no-pretty` – group findings by file and rule for easier human review (default off)

Each run reports which analysis engine was used (`semgrep` when available, otherwise a heuristic fallback) so you can confirm full rule coverage.

Example:

```bash
uniscan ~/Projects/MyUnityGame --format json --skip-binaries
```

### Run the test suite (optional)

```bash
pip install uniscan[test]
python -m pytest
```

---

## License

MIT License — see [LICENSE](../LICENSE) for details.

---

## Developer Notes

Semgrep rules live under `rules/core/semgrep`, one YAML file per rule. Generated rules (such as `unity.autorun.editor-hooks`) are driven by the data in `tools/semgrep/data` and a companion script under `tools/semgrep`. Re-run the generator after editing the spec:

```bash
python -m venv venv
source venv/bin/activate
python tools/semgrep/generate_autorun_editor_hooks.py
```

Commit the spec, generator, and regenerated YAML together so the rule bundle stays reproducible.
