"""Native binary detection helpers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


MAGIC_NUMBERS = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    bytes.fromhex("feedface"): "mach-o",
    bytes.fromhex("feedfacf"): "mach-o",
    bytes.fromhex("cffaedfe"): "mach-o",
    bytes.fromhex("cafebabe"): "mach-o-universal",
}

EXTENSION_KINDS = {
    ".dll": "dll",
    ".so": "so",
    ".dylib": "dylib",
    ".bundle": "bundle",
    ".framework": "framework",
    ".a": "static-lib",
}


@dataclass(frozen=True)
class BinaryFinding:
    path: Path
    kind: str
    size: int
    magic: Optional[str] = None


class BinaryClassifier:
    """Detect native binaries via extension or magic number heuristics."""

    def classify(self, path: Path) -> Optional[BinaryFinding]:
        kind = self._classify_extension(path)
        magic_label = None

        header = self._read_header(path)
        if header is None:
            return None

        magic_label = self._match_magic(header)
        if magic_label and not kind:
            kind = magic_label

        if not kind:
            return None

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        return BinaryFinding(path=path, kind=kind, size=size, magic=magic_label)

    @staticmethod
    def _classify_extension(path: Path) -> Optional[str]:
        suffix = path.suffix.lower()
        if suffix in EXTENSION_KINDS:
            return EXTENSION_KINDS[suffix]
        # Special handling for multi-part extensions (e.g., .bundle, .framework)
        name_lower = path.name.lower()
        for ext, label in EXTENSION_KINDS.items():
            if name_lower.endswith(ext):
                return label
        return None

    @staticmethod
    def _read_header(path: Path, length: int = 8) -> Optional[bytes]:
        try:
            with path.open("rb") as fh:
                return fh.read(length)
        except OSError:
            return None

    @staticmethod
    def _match_magic(header: bytes) -> Optional[str]:
        for magic, label in MAGIC_NUMBERS.items():
            if header.startswith(magic):
                return label
        return None
