"""Manifest helpers for mutable instruction files."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Iterable


class InstructionManifest:
    """Build and verify simple hash manifests for mutable instruction assets."""

    @staticmethod
    def fingerprint(path: Path) -> str:
        if not path.exists() or not path.is_file():
            return "missing"
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def build(cls, paths: Iterable[Path]) -> Dict[str, str]:
        return {str(path): cls.fingerprint(path) for path in paths}

    @classmethod
    def verify(cls, manifest: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        mismatches: Dict[str, Dict[str, str]] = {}
        for path_text, expected in manifest.items():
            actual = cls.fingerprint(Path(path_text))
            if actual != expected:
                mismatches[path_text] = {"expected": expected, "actual": actual}
        return mismatches
