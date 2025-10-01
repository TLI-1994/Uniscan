"""Helpers to invoke Semgrep for C# scanning."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import lru_cache

import certifi
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence


_DEFAULT_ENV: dict[str, str] = {
    "SEMGREP_SKIP_UPDATE_CHECK": "1",
    "SEMGREP_DISABLE_VERSION_CHECK": "1",
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_LOG_FILE": "/dev/null",
}


def _ensure_semgrep_environment(env: dict[str, str] | None = None) -> None:
    target = env if env is not None else os.environ
    for key, value in _DEFAULT_ENV.items():
        target.setdefault(key, value)
    target.setdefault("SSL_CERT_FILE", certifi.where())


class SemgrepUnavailable(RuntimeError):
    """Raised when Semgrep cannot be executed."""


@dataclass(frozen=True)
class SemgrepMatch:
    rule_id: str
    path: Path
    line: int | None
    end_line: int | None
    message: str | None
    severity: str | None
    snippet: str | None


class SemgrepRunner:
    """Thin wrapper around the Semgrep CLI."""

    def __init__(
        self,
        binary: str,
        rule_files: Sequence[Path],
        jobs: int | None = None,
        version: str | None = None,
    ) -> None:
        self.binary = binary
        self.rule_files = [Path(path) for path in rule_files]
        self.jobs = jobs
        self.version = version

    @classmethod
    def maybe_create(
        cls,
        rule_files: Sequence[Path],
        jobs: int | None = None,
    ) -> SemgrepRunner | None:
        binary = _resolve_semgrep_binary()
        if binary is None:
            return None
        _ensure_semgrep_environment()
        version = _detect_semgrep_version()
        return cls(binary, rule_files, jobs=jobs, version=version)

    def run(self, project_root: Path, targets: Sequence[Path]) -> list[SemgrepMatch]:
        if not targets:
            return []

        command: List[str] = [
            self.binary,
            "--json",
            "--quiet",
            "--disable-version-check",
            "--metrics", "off",
        ]
        for rule_path in self.rule_files:
            command.extend(["--config", str(rule_path)])
        jobs = self._effective_jobs(len(targets))
        if jobs and jobs > 1:
            command.extend(["--jobs", str(jobs)])
        command.extend(str(target) for target in targets)

        env = os.environ.copy()
        _ensure_semgrep_environment(env)

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=str(project_root),
                env=env,
                check=False,
            )
        except OSError as exc:  # pragma: no cover - unlikely but defensively handled
            raise SemgrepUnavailable(f"Failed to execute Semgrep: {exc}") from exc

        if proc.returncode != 0:
            raise SemgrepUnavailable(proc.stderr.strip() or "Semgrep exited with errors")

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:  # pragma: no cover - Semgrep guarantees JSON
            raise SemgrepUnavailable(f"Invalid Semgrep JSON output: {exc}") from exc

        matches: list[SemgrepMatch] = []
        results = payload.get("results", []) if isinstance(payload, dict) else []
        for entry in results:
            if not isinstance(entry, dict):
                continue
            rule_id = entry.get("check_id")
            if not rule_id:
                continue

            raw_path = entry.get("path")
            path_obj = Path(raw_path) if raw_path else project_root
            if not path_obj.is_absolute():
                path_obj = (project_root / path_obj).resolve()

            start = entry.get("start") or {}
            end = entry.get("end") or {}
            extra = entry.get("extra") or {}
            metadata = extra.get("metadata") or {}

            matches.append(
                SemgrepMatch(
                    rule_id=rule_id,
                    path=path_obj,
                    line=start.get("line"),
                    end_line=end.get("line"),
                    message=extra.get("message"),
                    severity=(metadata.get("severity") or extra.get("severity")),
                    snippet=extra.get("lines"),
                )
            )

        return matches


    def _effective_jobs(self, target_count: int) -> int | None:
        if not self.jobs or target_count <= 1:
            return None
        return max(1, min(self.jobs, target_count))


def _resolve_semgrep_binary() -> str | None:
    override = os.environ.get("USENTINEL_SEMGREP_BINARY") or os.environ.get("UNISCAN_SEMGREP_BINARY")
    if override:
        override_path = Path(override)
        if override_path.exists() and os.access(override_path, os.X_OK):
            return str(override_path)
        return None
    return shutil.which("semgrep")


@lru_cache(maxsize=1)
def _detect_semgrep_version() -> str | None:
    try:
        import semgrep  # type: ignore
    except Exception:  # pragma: no cover - dependency load failure
        return None

    version = getattr(semgrep, "__VERSION__", None) or getattr(semgrep, "__version__", None)
    return str(version) if isinstance(version, str) else None
