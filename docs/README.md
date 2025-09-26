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

### 3. Run the scanner:
Run the main Python script, providing the path to the Unity project you want to audit.
```bash
python src/uniscan/main.py /path/to/unity/project
```

Or, if installed as a package with an entry point:
```bash
uniscan /path/to/unity/project
```

---

## License

MIT License — see [LICENSE](../LICENSE) for details.
