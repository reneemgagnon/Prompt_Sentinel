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

    return ValidationResult(ok=not errors, errors=errors, warnings=warnings)
