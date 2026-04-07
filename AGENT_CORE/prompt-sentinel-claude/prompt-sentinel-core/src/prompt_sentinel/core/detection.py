"""Pattern-based risk detection and alert helpers."""

from __future__ import annotations

from typing import Dict, List


PROMPT_OVERRIDE_PATTERNS = (
    "ignore previous instructions",
    "disregard system prompt",
    "reveal hidden policy",
    "show me your system prompt",
)

BLOCK_PATTERNS = (".env", ".git/", "id_rsa", "secret", "deploy", "bypass")
ASK_PATTERNS = ("curl", "ssh", "scp", "export", "token")


def detect_prompt_patterns(text: str) -> List[str]:
    lower = text.lower()
    return [pattern for pattern in PROMPT_OVERRIDE_PATTERNS if pattern in lower]


def detect_tool_text(text: str) -> Dict[str, List[str]]:
    lower = text.lower()
    return {
        "block": [pattern for pattern in BLOCK_PATTERNS if pattern in lower],
        "ask": [pattern for pattern in ASK_PATTERNS if pattern in lower],
    }
