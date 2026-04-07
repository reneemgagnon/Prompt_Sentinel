"""Resolve bundled Prompt_Sentinel assets without requiring installation."""

from __future__ import annotations

import sys
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
LEGACY_AGENT_CORE = Path(__file__).resolve().parents[4] / "AGENT_CORE"


def _resolve_existing_path(candidates: list[Path], *, kind: str) -> Path:
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"Could not locate {kind}. Checked: "
        + ", ".join(str(candidate) for candidate in candidates)
    )


def resolve_core_src() -> Path:
    return _resolve_existing_path(
        [
            Path.cwd() / "AGENT_CORE" / "prompt-sentinel-claude" / "prompt-sentinel-core" / "src",
            SKILL_ROOT / "prompt-sentinel-core" / "src",
            SKILL_ROOT / "core" / "src",
            SKILL_ROOT / "vendor" / "prompt-sentinel-core" / "src",
            LEGACY_AGENT_CORE / "prompt-sentinel-claude" / "prompt-sentinel-core" / "src",
            LEGACY_AGENT_CORE / "prompt-sentinel-core" / "src",
        ],
        kind="prompt-sentinel-core/src",
    )


def resolve_default_policy_path() -> Path:
    return _resolve_existing_path(
        [
            Path.cwd() / "AGENT_CORE" / "prompt-sentinel-claude" / "prompt-sentinel-core" / "src" / "prompt_sentinel" / "policies" / "default-policy.json",
            SKILL_ROOT / "policies" / "default-policy.json",
            SKILL_ROOT / "policies" / "codex-default-policy.json",
            Path.cwd() / "policies" / "default-policy.json",
            Path.cwd() / "policies" / "codex-default-policy.json",
            Path.cwd() / "policies" / "claude-default-policy.json",
            LEGACY_AGENT_CORE / "prompt-sentinel-claude" / "prompt-sentinel-core" / "src" / "prompt_sentinel" / "policies" / "default-policy.json",
            LEGACY_AGENT_CORE / "prompt-sentinel-codex" / "policies" / "codex-default-policy.json",
        ],
        kind="default policy file",
    )


CORE_SRC = resolve_core_src()
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))