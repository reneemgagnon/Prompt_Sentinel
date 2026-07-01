"""Validation helpers for Prompt_Sentinel policies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class ValidationIssue:
    level: str
    path: str
    message: str


@dataclass
class ValidationResult:
    ok: bool
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "errors": [issue.__dict__ for issue in self.errors],
            "warnings": [issue.__dict__ for issue in self.warnings],
        }


def _issue(level: str, path: str, message: str) -> ValidationIssue:
    return ValidationIssue(level=level, path=path, message=message)


def validate_policy(policy: Dict[str, Any]) -> ValidationResult:
    errors: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []

    if not isinstance(policy, dict):
        return ValidationResult(
            ok=False,
            errors=[_issue("error", "$", "policy must be a JSON object")],
        )

    permissions = policy.get("tool_permissions")
    if not isinstance(permissions, dict) or not permissions:
        errors.append(_issue("error", "tool_permissions", "tool_permissions must be a non-empty object"))
        return ValidationResult(ok=False, errors=errors, warnings=warnings)

    for tool_name, rules in permissions.items():
        tool_path = f"tool_permissions.{tool_name}"
        if not isinstance(tool_name, str) or not tool_name.strip():
            errors.append(_issue("error", tool_path, "tool name must be a non-empty string"))
            continue
        if not isinstance(rules, dict):
            errors.append(_issue("error", tool_path, "tool rules must be an object"))
            continue

        allowed_params = rules.get("allowed_params")
        if allowed_params is not None:
            if not isinstance(allowed_params, list) or not all(isinstance(item, str) and item.strip() for item in allowed_params):
                errors.append(_issue("error", f"{tool_path}.allowed_params", "allowed_params must be a list of non-empty strings"))

        whitelist = rules.get("path_whitelist")
        if whitelist is not None:
            if not isinstance(whitelist, list) or not all(isinstance(item, str) and item.strip() for item in whitelist):
                errors.append(_issue("error", f"{tool_path}.path_whitelist", "path_whitelist must be a list of non-empty strings"))
            if tool_name != "file_read":
                warnings.append(_issue("warning", f"{tool_path}.path_whitelist", "path_whitelist is usually only meaningful for file_read"))

        max_calls = rules.get("max_calls_per_session")
        if max_calls is not None:
            if not isinstance(max_calls, int) or max_calls <= 0:
                errors.append(_issue("error", f"{tool_path}.max_calls_per_session", "max_calls_per_session must be a positive integer"))

        retention_class = rules.get("retention_class")
        if retention_class is not None and (not isinstance(retention_class, str) or not retention_class.strip()):
            errors.append(_issue("error", f"{tool_path}.retention_class", "retention_class must be a non-empty string"))

        sensitive_class = rules.get("sensitive_action_class")
        if sensitive_class is not None and (not isinstance(sensitive_class, str) or not sensitive_class.strip()):
            errors.append(_issue("error", f"{tool_path}.sensitive_action_class", "sensitive_action_class must be a non-empty string"))

        approval_scope = rules.get("approval_scope")
        if approval_scope is not None and not isinstance(approval_scope, str):
            errors.append(_issue("error", f"{tool_path}.approval_scope", "approval_scope must be a string"))

        approval_operation = rules.get("approval_operation")
        if approval_operation is not None and (not isinstance(approval_operation, str) or not approval_operation.strip()):
            errors.append(_issue("error", f"{tool_path}.approval_operation", "approval_operation must be a non-empty string"))

    capability_required = policy.get("capability_required_tools", [])
    if capability_required is not None:
        if not isinstance(capability_required, list) or not all(isinstance(item, str) and item.strip() for item in capability_required):
            errors.append(_issue("error", "capability_required_tools", "capability_required_tools must be a list of non-empty strings"))
        else:
            unknown = [tool for tool in capability_required if tool not in permissions]
            if unknown:
                errors.append(_issue("error", "capability_required_tools", f"references unknown tools: {unknown}"))

    inheritance = policy.get("inheritance")
    if inheritance is not None:
        if not isinstance(inheritance, dict):
            errors.append(_issue("error", "inheritance", "inheritance must be an object"))
        else:
            parents = inheritance.get("extends", [])
            if parents and (not isinstance(parents, list) or not all(isinstance(item, str) and item.strip() for item in parents)):
                errors.append(_issue("error", "inheritance.extends", "inheritance.extends must be a list of non-empty strings"))

    meta = policy.get("meta")
    if meta is not None and not isinstance(meta, dict):
        errors.append(_issue("error", "meta", "meta must be an object"))

    if "sensitive_action_classes" in policy:
        classes = policy["sensitive_action_classes"]
        if not isinstance(classes, dict):
            errors.append(_issue("error", "sensitive_action_classes", "sensitive_action_classes must be an object"))

    mcp_servers = policy.get("mcp_servers")
    if mcp_servers is not None:
        if not isinstance(mcp_servers, dict):
            errors.append(_issue("error", "mcp_servers", "mcp_servers must be an object"))
        else:
            for server_id, server_rules in mcp_servers.items():
                server_path = f"mcp_servers.{server_id}"
                if not isinstance(server_id, str) or not server_id.strip():
                    errors.append(_issue("error", server_path, "MCP server id must be a non-empty string"))
                    continue
                if not isinstance(server_rules, dict):
                    errors.append(_issue("error", server_path, "MCP server rules must be an object"))
                    continue
                transport = server_rules.get("transport")
                if transport is not None and str(transport) not in {"stdio", "http", "streamable-http", "sse"}:
                    errors.append(_issue("error", f"{server_path}.transport", "unsupported MCP transport"))
                trust_tier = server_rules.get("trust_tier")
                if trust_tier is not None and (not isinstance(trust_tier, str) or not trust_tier.strip()):
                    errors.append(_issue("error", f"{server_path}.trust_tier", "trust_tier must be a non-empty string"))
                tools = server_rules.get("tools")
                if not isinstance(tools, dict) or not tools:
                    errors.append(_issue("error", f"{server_path}.tools", "approved MCP servers must pin at least one tool"))
                    continue
                for tool_id, tool_rules in tools.items():
                    mcp_tool_path = f"{server_path}.tools.{tool_id}"
                    if not isinstance(tool_id, str) or not tool_id.strip():
                        errors.append(_issue("error", mcp_tool_path, "MCP tool name must be a non-empty string"))
                        continue
                    if not isinstance(tool_rules, dict):
                        errors.append(_issue("error", mcp_tool_path, "MCP tool rules must be an object"))
                        continue
                    schema_hash = tool_rules.get("schema_hash")
                    if schema_hash is not None and (not isinstance(schema_hash, str) or len(schema_hash) != 64):
                        errors.append(_issue("error", f"{mcp_tool_path}.schema_hash", "schema_hash must be a 64-character hex string"))
                    elif schema_hash is None and not server_rules.get("allow_unpinned_tools", False):
                        warnings.append(_issue("warning", f"{mcp_tool_path}.schema_hash", "MCP tool is approved without a schema pin"))
                    allowed_params = tool_rules.get("allowed_params")
                    if allowed_params is not None:
                        if not isinstance(allowed_params, list) or not all(isinstance(item, str) and item.strip() for item in allowed_params):
                            errors.append(_issue("error", f"{mcp_tool_path}.allowed_params", "allowed_params must be a list of non-empty strings"))
                    approval_operation = tool_rules.get("approval_operation")
                    if approval_operation is not None and (not isinstance(approval_operation, str) or not approval_operation.strip()):
                        errors.append(_issue("error", f"{mcp_tool_path}.approval_operation", "approval_operation must be a non-empty string"))

    flows = policy.get("mcp_data_flows")
    if flows is not None:
        if not isinstance(flows, dict):
            errors.append(_issue("error", "mcp_data_flows", "mcp_data_flows must be an object"))
        else:
            for flow_key in ("allowed", "blocked"):
                edges = flows.get(flow_key, [])
                if not isinstance(edges, list):
                    errors.append(_issue("error", f"mcp_data_flows.{flow_key}", "flow edges must be a list"))
                    continue
                for index, edge in enumerate(edges):
                    if not isinstance(edge, dict) or not isinstance(edge.get("from"), str) or not isinstance(edge.get("to"), str):
                        errors.append(_issue("error", f"mcp_data_flows.{flow_key}[{index}]", "flow edge must contain string from/to values"))

    return ValidationResult(ok=not errors, errors=errors, warnings=warnings)
