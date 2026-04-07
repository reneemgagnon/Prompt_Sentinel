"""Resolve the local prompt-sentinel-core package without requiring installation."""

from __future__ import annotations

import sys
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = Path(__file__).resolve().parents[7]


def _resolve_existing_path(candidates: list[Path]) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not locate prompt-sentinel-core/src. Checked: "
        + ", ".join(str(candidate) for candidate in candidates)
    )


CORE_SRC = _resolve_existing_path(
    [
        WORKSPACE_ROOT / "AGENT_CORE" / "prompt-sentinel-claude" / "prompt-sentinel-core" / "src",
        WORKSPACE_ROOT / "AGENT_CORE" / "prompt-sentinel-core" / "src",
        SKILL_ROOT / "prompt-sentinel-core" / "src",
    ]
)
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))