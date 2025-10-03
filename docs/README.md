# Usentinel

[![PyPI](https://img.shields.io/pypi/v/usentinel.svg?label=PyPI)](https://pypi.org/project/usentinel/) [![Python Versions](https://img.shields.io/pypi/pyversions/usentinel.svg)](https://pypi.org/project/usentinel/) [![License](https://img.shields.io/pypi/l/usentinel.svg)](https://github.com/TLI-1994/Usentinel/blob/main/LICENSE) [![CI](https://github.com/TLI-1994/Usentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/TLI-1994/Usentinel/actions/workflows/ci.yml)

**Usentinel** is a **lightweight command-line interface (CLI) tool** designed to **audit Unity projects** for potentially hazardous code and native binaries. It inspects project files without modifying them, writing reports (HTML or JSON) to the location you choose.

### Key Features
* **Static Code Analysis:** Scans C# scripts for common security vulnerabilities and anti-patterns.
* **Binary Detection:** Identifies native binary files (e.g., `.dll`, `.so`, `.dylib`) which can sometimes pose a risk.
* **Clear Summary Output:** Presents findings with severity and file locations so you can investigate quickly.
* **Minimal Footprint:** Usentinel analyzes projects without changing their contents and has minimal runtime dependencies.

---

## Installation & Usage

Install from PyPI:

```bash
pip install usentinel
```

Then scan your Unity project:

```bash
usentinel /path/to/unity/project
```

Each scan writes a polished HTML report to the current directory (for example `usentinel-report-myproject-20240518-172455-a1b2c3d4.html`). Open it in your browser, or pass a folder to `--output` to place reports elsewhere.

Prefer working from source?

```bash
git clone https://github.com/TLI-1994/Usentinel.git
cd Usentinel
PYTHONPATH=src python -m usentinel.main /path/to/unity/project
```

Common flags:

* `--format {html|raw}` (default: `html`) – open-friendly HTML or raw JSON for automation (`json` is accepted as an alias for `raw`).
* `--output PATH` – when using HTML, write to a specific file or directory (defaults to `usentinel-report-<project>-YYYYMMDD-HHMMSS-<hash>.html`).
* `--ruleset path/to/extra_rules.yaml` – load additional Semgrep-style YAML rules (repeatable).
* `--include-binaries` / `--skip-binaries` (default: include) – control native binary detection.
* `--engine {auto|heuristic|semgrep}` (default: `auto`) – auto-select, force the heuristic engine, or use Semgrep.
* `--version` – print the installed Usentinel version and exit.

Progress indicators show automatically when Usentinel runs in an interactive terminal and stay quiet when output is redirected, so you can safely pipe results into other tools without extra flags.

Each run reports which analysis engine was used (`semgrep` when available, otherwise a heuristic fallback) so you can confirm coverage.

Prefer raw JSON? Swap the format flag:

```bash
usentinel ~/Projects/MyUnityGame --format raw
```

The JSON output mirrors the HTML report data so you can integrate it with other tools or pipelines.

### Run the test suite (contributors)

If you are contributing to Usentinel, install the project in editable mode with the
testing extras and run the suite from the repository root:

```bash
pip install -e '.[test]'
python -m pytest
```

---

## License

MIT License — see [LICENSE](https://github.com/TLI-1994/Usentinel/blob/main/LICENSE) for details.

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

* **Best-effort analysis:** Usentinel performs static, non-destructive analysis. It highlights patterns worth human review but it is not a substitute for a professional security audit, and it cannot detect every risky construct in the Unity ecosystem.
* **Your responsibility:** You remain solely responsible for validating findings, performing additional due diligence, and complying with all applicable laws and regulations.
* **No warranties:** The tool is provided “AS IS” without express or implied warranties, including but not limited to implied warranties of merchantability, fitness for a particular purpose, non-infringement, security, or error-free operation.
* **No liability:** In no event shall the authors or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising out of or in connection with the use of Usentinel or reliance on its results. By using Usentinel you acknowledge these limitations and agree to hold the authors and contributors harmless.

Feedback and contributions are welcome. If you spot gaps in rule coverage or encounter issues, please open an issue or pull request on GitHub so we can improve together.
