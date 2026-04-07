#!/usr/bin/env python3
"""Generate an instruction manifest that covers config AND hook files.

Usage (from project root):
    python .claude/scripts/generate_manifest.py > .claude/prompt-sentinel.manifest.json

The manifest is consumed by trusted_launch.py at session start to detect
mid-session tampering of instruction files or hook scripts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Resolve the core package for InstructionManifest
CORE_SRC = Path(__file__).resolve().parents[2] / "prompt-sentinel-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from prompt_sentinel.core.manifests import InstructionManifest  # noqa: E402

MANIFEST_PATHS = [
    Path("CLAUDE.md"),
    Path(".claude/settings.json"),
    Path(".claude/settings.local.json"),
    Path(".claude/hooks/common.py"),
    Path(".claude/hooks/trusted_launch.py"),
    Path(".claude/hooks/user_prompt_submit.py"),
    Path(".claude/hooks/pre_tool_firewall.py"),
    Path(".claude/hooks/config_tamper_alert.py"),
    Path(".claude/hooks/post_tool_use.py"),
    Path(".claude/hooks/stop.py"),
]


def main() -> int:
    manifest = InstructionManifest.build(MANIFEST_PATHS)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
