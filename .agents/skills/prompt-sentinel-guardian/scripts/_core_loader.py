"""Resolve the local prompt-sentinel-core package without requiring installation."""

from __future__ import annotations

import sys
from pathlib import Path


CORE_SRC = Path(__file__).resolve().parents[4] / "AGENT_CORE" / "prompt-sentinel-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))
