# Uniscan

[![PyPI](https://img.shields.io/pypi/v/uniscan.svg?label=PyPI)](https://pypi.org/project/uniscan/)

**Uniscan** is a **lightweight, read-only command-line interface (CLI) tool** designed to **audit Unity projects** for potentially hazardous code and native binaries. It provides static checks that highlight code patterns worth deeper inspection.

### Key Features
* **Static Code Analysis:** Scans C# scripts for common security vulnerabilities and anti-patterns.
* **Binary Detection:** Identifies native binary files (e.g., `.dll`, `.so`, `.dylib`) which can sometimes pose a risk.
* **Clear Summary Output:** Presents findings with severity and file locations so you can investigate quickly.
* **Minimal Footprint:** Uniscan is read-only and has minimal runtime dependencies.

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

Prefer working from source?

```bash
git clone https://github.com/TLI-1994/Uniscan.git
cd Uniscan
PYTHONPATH=src python -m uniscan.main /path/to/unity/project
```

Common flags:

* `--format {text|json}` (default: `text`) – choose human-readable or machine-readable output.
* `--no-colors` (default: off) – disable ANSI colours in text mode.
* `--ruleset path/to/extra_rules.yaml` – load additional Semgrep-style YAML rules (repeatable).
* `--include-binaries` / `--skip-binaries` (default: include) – control native binary detection.
* `--verbosity {quiet|normal|debug}` (default: `normal`) – adjust the amount of detail (`--quiet` / `--debug` aliases).
* `--engine {auto|heuristic|semgrep}` (default: `auto`) – auto-select, force the heuristic engine, or use Semgrep.
* `--progress` / `--no-progress` (default: progress on) – toggle the live progress indicator.
* `--pretty` / `--no-pretty` (default: grouped off) – group findings by file and rule for easier human review.
* `--version` – print the installed Uniscan version and exit.

> **Semgrep snippets:** When the Semgrep engine runs, `--verbosity debug` displays code snippets. For community rules, Semgrep returns snippets only if you run `semgrep login`; otherwise the placeholder `requires login` appears. Findings still include file paths and line numbers so you can review the code manually.

Each run reports which analysis engine was used (`semgrep` when available, otherwise a heuristic fallback) so you can confirm coverage.

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

MIT License — see [LICENSE](https://github.com/TLI-1994/Uniscan/blob/main/LICENSE) for details.

---

## Developer Notes

Semgrep rules live under `rules/core/semgrep`, one YAML file per rule. Generated rules (such as `unity.autorun.editor-hooks`) are driven by the data in `tools/semgrep/data` and a companion script under `tools/semgrep`. Re-run the generator after editing the spec:

```bash
python -m venv venv
source venv/bin/activate
python tools/semgrep/generate_autorun_editor_hooks.py
```

Commit the spec, generator, and regenerated YAML together so the rule bundle stays reproducible.

---

## Disclaimer

In addition to the MIT License notice, please keep the following in mind:

* **Best-effort analysis:** Uniscan is a read-only static-analysis aid. It highlights patterns worth human review but it is not a substitute for a professional security audit, and it cannot detect every risky construct in the Unity ecosystem.
* **Your responsibility:** You remain solely responsible for validating findings, performing additional due diligence, and complying with all applicable laws and regulations.
* **No warranties:** The tool is provided “AS IS” without express or implied warranties, including but not limited to implied warranties of merchantability, fitness for a particular purpose, non-infringement, security, or error-free operation.
* **No liability:** In no event shall the authors or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising out of or in connection with the use of Uniscan or reliance on its results. By using Uniscan you acknowledge these limitations and agree to hold the authors and contributors harmless.

Feedback and contributions are welcome. If you spot gaps in rule coverage or encounter issues, please open an issue or pull request on GitHub so we can improve together.
