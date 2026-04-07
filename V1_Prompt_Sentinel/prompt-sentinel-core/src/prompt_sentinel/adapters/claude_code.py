"""Claude Code hook helpers."""

from __future__ import annotations

from typing import Any, Dict


def deny_response(reason: str) -> Dict[str, Any]:
    return {
        "decision": "deny",
        "reason": reason,
    }


def allow_response(additional_context: str = "") -> Dict[str, Any]:
    response: Dict[str, Any] = {"decision": "allow"}
    if additional_context:
        response["additionalContext"] = additional_context
    return response


def ask_response(reason: str) -> Dict[str, Any]:
    return {
        "decision": "ask",
        "reason": reason,
    }
