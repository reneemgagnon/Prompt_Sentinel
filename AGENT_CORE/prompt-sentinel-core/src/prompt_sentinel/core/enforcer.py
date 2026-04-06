"""Host-side policy checks."""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, Tuple

from .models import SessionFacts


class PolicyEnforcer:
    """Evaluate tool proposals against an in-memory policy."""

    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy
        self._tool_counts_by_session: Dict[str, Dict[str, int]] = {}

    def _bump_tool_count(self, session_id: str, tool: str) -> int:
        by_tool = self._tool_counts_by_session.setdefault(session_id, {})
        by_tool[tool] = by_tool.get(tool, 0) + 1
        return by_tool[tool]

    def check_tool_call(self, *, session: SessionFacts, tool: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        permissions = self.policy.get("tool_permissions") or {}
        if tool not in permissions:
            return False, f"tool '{tool}' is not allowed"

        rules = permissions[tool] or {}
        allowed_params = rules.get("allowed_params")
        if isinstance(allowed_params, list):
            unknown = [name for name in params if name not in allowed_params]
            if unknown:
                return False, f"unknown params for {tool}: {unknown}"

        if "path_whitelist" in rules:
            path = str(params.get("path", ""))
            if not path:
                return False, "missing required param: path"
            if not any(fnmatch.fnmatch(path, pattern) for pattern in rules["path_whitelist"]):
                return False, "path not allowlisted"

        if "max_calls_per_session" in rules:
            count = self._bump_tool_count(session.session_id, tool)
            if count > int(rules["max_calls_per_session"]):
                return False, f"tool quota exceeded ({count}>{rules['max_calls_per_session']})"

        return True, "permitted by policy"

    def capability_required(self, *, tool: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        required = set(self.policy.get("capability_required_tools") or [])
        if tool in required:
            return True, "capability required by tool classification"

        if tool == "file_read":
            path = str(params.get("path", ""))
            if "secret" in path.lower() or "patient" in path.lower():
                return True, "capability required by sensitive path heuristic"

        return False, "no capability required"
