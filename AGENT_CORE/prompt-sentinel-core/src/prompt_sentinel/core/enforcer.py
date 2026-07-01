"""Host-side policy checks."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .models import SessionFacts
from .mcp import (
    check_mcp_data_flow,
    find_sensitive_payload,
    get_mcp_servers,
    parse_mcp_tool_name,
    validate_mcp_server_config,
)


class PolicyEnforcer:
    """Evaluate tool proposals against an in-memory policy."""

    def __init__(self, policy: Dict[str, Any], *, base_dir: Optional[Path] = None):
        self.policy = policy
        self.base_dir = Path(base_dir or ".").resolve()
        self._tool_counts_by_session: Dict[str, Dict[str, int]] = {}

    def _bump_tool_count(self, session_id: str, tool: str) -> int:
        by_tool = self._tool_counts_by_session.setdefault(session_id, {})
        by_tool[tool] = by_tool.get(tool, 0) + 1
        return by_tool[tool]

    def _canonical_relative_path(self, path_text: str) -> Tuple[Optional[str], str]:
        if not path_text:
            return None, "missing required param: path"
        try:
            candidate = Path(path_text).expanduser()
            candidate = (self.base_dir / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        except OSError:
            return None, "path could not be resolved"
        if self.base_dir not in candidate.parents and candidate != self.base_dir:
            return None, "path outside base_dir"
        if candidate == self.base_dir:
            return ".", "resolved"
        return candidate.relative_to(self.base_dir).as_posix(), "resolved"

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        return pattern.replace("\\", "/").lstrip("./")

    def _path_allowlisted(self, *, path_text: str, patterns: Any) -> Tuple[bool, str]:
        rel_path, reason = self._canonical_relative_path(path_text)
        if rel_path is None:
            return False, reason
        normalized_patterns = [self._normalize_pattern(str(pattern)) for pattern in patterns]
        if not any(fnmatch.fnmatch(rel_path, pattern) for pattern in normalized_patterns):
            return False, "path not allowlisted"
        return True, "path allowlisted"

    def _mcp_ref(self, tool: str, metadata: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        server_id = metadata.get("mcp_server_id") or metadata.get("server_id")
        mcp_tool_name = metadata.get("mcp_tool_name") or metadata.get("tool_name")
        if server_id and mcp_tool_name:
            return str(server_id), str(mcp_tool_name)
        return parse_mcp_tool_name(tool)

    def _check_mcp_tool_call(
        self,
        *,
        session: SessionFacts,
        tool: str,
        params: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Tuple[bool, str]:
        mcp_ref = self._mcp_ref(tool, metadata)
        if mcp_ref is None:
            return False, "invalid MCP tool identity"
        server_id, mcp_tool_name = mcp_ref
        server_rule = get_mcp_servers(self.policy).get(server_id)
        if not isinstance(server_rule, dict):
            return False, f"MCP server '{server_id}' is not allowed"
        if server_rule.get("enabled", True) is False:
            return False, f"MCP server '{server_id}' is disabled"
        config_errors = validate_mcp_server_config(server_rule, self.policy)
        if config_errors:
            return False, f"MCP server config denied: {config_errors[0]}"
        tool_rules = (server_rule.get("tools") or {}).get(mcp_tool_name)
        if not isinstance(tool_rules, dict):
            return False, f"MCP tool '{server_id}/{mcp_tool_name}' is not pinned"

        expected_hash = tool_rules.get("schema_hash")
        actual_hash = metadata.get("schema_hash") or metadata.get("mcp_schema_hash")
        if expected_hash and not actual_hash:
            return False, "missing MCP schema hash for pinned tool"
        if expected_hash and str(expected_hash) != str(actual_hash):
            return False, "MCP schema hash mismatch"

        allowed_params = tool_rules.get("allowed_params")
        if isinstance(allowed_params, list):
            unknown = [name for name in params if name not in allowed_params]
            if unknown:
                return False, f"unknown params for MCP tool {server_id}/{mcp_tool_name}: {unknown}"

        input_origins = metadata.get("input_origins") or metadata.get("mcp_input_origins") or []
        if isinstance(input_origins, str):
            input_origins = [input_origins]
        if isinstance(input_origins, list):
            ok, flow_reason = check_mcp_data_flow(
                self.policy,
                source_servers=[str(origin) for origin in input_origins],
                target_server=server_id,
            )
            if not ok:
                return False, flow_reason

        trust_tier = str(server_rule.get("trust_tier", "untrusted")).lower()
        if trust_tier in {"third-party", "untrusted", "external"} and not tool_rules.get("allow_sensitive_payloads", False):
            findings = find_sensitive_payload(params, self.policy)
            if findings:
                return False, f"sensitive payload to {trust_tier} MCP server requires explicit policy allowance"

        if "max_calls_per_session" in tool_rules:
            count = self._bump_tool_count(session.session_id, tool)
            if count > int(tool_rules["max_calls_per_session"]):
                return False, f"tool quota exceeded ({count}>{tool_rules['max_calls_per_session']})"
        return True, "permitted by MCP policy"

    def check_tool_call(
        self,
        *,
        session: SessionFacts,
        tool: str,
        params: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        metadata = metadata or {}
        if self._mcp_ref(tool, metadata) is not None:
            return self._check_mcp_tool_call(session=session, tool=tool, params=params, metadata=metadata)

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
            allowed, path_reason = self._path_allowlisted(path_text=path, patterns=rules["path_whitelist"])
            if not allowed:
                return False, path_reason

        if "max_calls_per_session" in rules:
            count = self._bump_tool_count(session.session_id, tool)
            if count > int(rules["max_calls_per_session"]):
                return False, f"tool quota exceeded ({count}>{rules['max_calls_per_session']})"

        return True, "permitted by policy"

    def _rules_for_tool(self, tool: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        metadata = metadata or {}
        mcp_ref = self._mcp_ref(tool, metadata)
        if mcp_ref is not None:
            server_id, mcp_tool_name = mcp_ref
            server_rule = get_mcp_servers(self.policy).get(server_id) or {}
            return (server_rule.get("tools") or {}).get(mcp_tool_name) or {}
        return (self.policy.get("tool_permissions") or {}).get(tool) or {}

    def capability_required(self, *, tool: str, params: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        required = set(self.policy.get("capability_required_tools") or [])
        if tool in required:
            return True, "capability required by tool classification"

        rules = self._rules_for_tool(tool, metadata)
        if rules.get("capability_required") is True:
            return True, "capability required by MCP tool classification"
        sensitive_class = str(rules.get("sensitive_action_class", "")).lower()
        if sensitive_class in {"privileged", "restricted", "approval-gated"}:
            return True, f"capability required by sensitive action class '{sensitive_class}'"

        if tool == "file_read":
            path = str(params.get("path", ""))
            if "secret" in path.lower() or "patient" in path.lower():
                return True, "capability required by sensitive path heuristic"

        return False, "no capability required"

    def capability_context(self, *, tool: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rules = self._rules_for_tool(tool, metadata)
        scope = {"tool": tool}
        if metadata:
            mcp_ref = self._mcp_ref(tool, metadata)
            if mcp_ref is not None:
                scope["mcp_server_id"], scope["mcp_tool_name"] = mcp_ref
        if "approval_scope" in rules:
            scope["approval_scope"] = rules["approval_scope"]
        return {
            "operation": rules.get("approval_operation", "approve_tool_call"),
            "scope": scope,
        }

    def tool_metadata(self, tool: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return audit-friendly metadata for the configured tool."""
        source_metadata = metadata or {}
        rules = self._rules_for_tool(tool, source_metadata)
        audit_metadata = {
            "policy_name": ((self.policy.get("meta") or {}).get("policy_name") or "unnamed-policy"),
            "retention_class": rules.get("retention_class", "standard"),
            "sensitive_action_class": rules.get("sensitive_action_class", "standard"),
        }
        mcp_ref = self._mcp_ref(tool, source_metadata)
        if mcp_ref is not None:
            server_id, mcp_tool_name = mcp_ref
            audit_metadata["mcp_server_id"] = server_id
            audit_metadata["mcp_tool_name"] = mcp_tool_name
            schema_hash = source_metadata.get("schema_hash") or source_metadata.get("mcp_schema_hash")
            if schema_hash:
                audit_metadata["mcp_schema_hash"] = schema_hash
        if "approval_scope" in rules:
            audit_metadata["approval_scope"] = rules["approval_scope"]
        return audit_metadata
