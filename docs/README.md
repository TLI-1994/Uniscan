# Uniscan

**Uniscan** is a **lightweight, read-only command-line interface (CLI) tool** designed to **audit Unity projects** for potentially hazardous code and native binaries. It's a quick and simple way to get a security overview of your project without needing a complex setup. The tool scans C# scripts for risky patterns and provides a clear, color-coded summary directly in your terminal.

### Key Features
* **Static Code Analysis:** Scans C# scripts for common security vulnerabilities and anti-patterns.
* **Binary Detection:** Identifies native binary files (e.g., `.dll`, `.so`, `.dylib`) which can sometimes pose a risk.
* **Clear, Color-Coded Output:** Provides an easy-to-read summary of findings, highlighting issues with different colors.
* **Minimalist Design:** It's read-only, has minimal dependencies, and won't modify your project.

---

## Installation & Usage

You can use Uniscan directly from its source code. No complex installation is required.

### 1. Clone the repository

First, clone the project from GitHub:

```bash
git clone https://github.com/TLI-1994/Uniscan.git
```

### 2. Navigate to the directory
Change your current directory to the cloned repository:
```bash
cd Uniscan
```

### 3. Run the scanner

Run the CLI against your Unity project. From the repository root you can execute the module directly:

```bash
PYTHONPATH=src python -m uniscan.main /path/to/unity/project
```

If you install the package into a virtual environment, the console script becomes available:

```bash
pip install .
uniscan /path/to/unity/project
```

Common flags:

* `--format {text|json}` – choose human-readable or machine-readable output (`text` is default)
* `--no-colors` – disable ANSI colours in text mode
* `--ruleset path/to/extra_rules.yaml` – load additional Semgrep-style YAML rules (may be passed multiple times)
* `--skip-binaries` / `--include-binaries` – control native binary detection
* `--verbosity {quiet|normal|debug}` – adjust the amount of detail printed (aliases `--quiet` and `--debug`)

Example:

```bash
uniscan ~/Projects/MyUnityGame --format json --skip-binaries
```

### 4. Run the test suite (optional)

Install the testing extra and execute pytest:

```bash
pip install .[test]
python -m pytest
```

---

## License

MIT License — see [LICENSE](../LICENSE) for details.
