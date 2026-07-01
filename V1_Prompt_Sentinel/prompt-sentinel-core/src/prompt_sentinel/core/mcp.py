"""MCP admission, pinning, and data-flow helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .utils import canonical_json, sha256_hex

MCP_TOOL_PREFIX = "mcp__"
MCP_ALT_PREFIX = "mcp:"

PROMPT_RISK_PATTERNS = (
    "ignore previous instructions",
    "disregard system prompt",
    "do not mention",
    "do not tell",
    "hidden instruction",
    "secretly",
    "before using this tool",
    "pass its content",
    "provide the content",
    "read ~/.ssh",
    "~/.ssh/id_rsa",
    "id_rsa",
    ".env",
    "api key",
    "token",
    "exfiltrate",
    "send all",
    "append the content",
)

OUTPUT_REQUEST_PATTERNS = (
    "provide the content",
    "read the file",
    "read ~/.ssh",
    "id_rsa",
    ".env",
    "api key",
    "secret",
    "token",
    "append the content",
)

SENSITIVE_PAYLOAD_PATTERNS = (
    "-----begin ",
    "private key",
    "id_rsa",
    ".env",
    "api_key",
    "api key",
    "access token",
    "refresh token",
    "password",
    "invoice",
    "ssn",
)

STDIO_DANGEROUS_TOKENS = (";", "&&", "||", "|", ">", "<", "`", "$(", "\n", "\r")
DEFAULT_STDIO_COMMANDS = ("python", "python3", "node", "npx", "uvx")


def parse_mcp_tool_name(tool_name: str) -> Optional[Tuple[str, str]]:
    """Return (server_id, tool_name) for common MCP host tool naming schemes."""
    if tool_name.startswith(MCP_TOOL_PREFIX):
        remainder = tool_name[len(MCP_TOOL_PREFIX) :]
        if "__" not in remainder:
            return None
        server_id, mcp_tool = remainder.split("__", 1)
        if server_id and mcp_tool:
            return server_id, mcp_tool
    if tool_name.startswith(MCP_ALT_PREFIX):
        parts = tool_name.split(":", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
    return None


def iter_text_fragments(value: Any, path: str = "$") -> Iterable[Tuple[str, str]]:
    """Yield all string-like fragments, including object keys, for prompt-risk scans."""
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            key_path = f"{path}.{key_text}"
            yield key_path, key_text
            yield from iter_text_fragments(child, key_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_text_fragments(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def canonical_mcp_tool_descriptor(tool_definition: Dict[str, Any]) -> Dict[str, Any]:
    """Return a stable descriptor representation for pinning and review."""
    return dict(tool_definition)


def mcp_tool_schema_hash(tool_definition: Dict[str, Any]) -> str:
    return sha256_hex(canonical_json(canonical_mcp_tool_descriptor(tool_definition)))


def detect_mcp_descriptor_risks(tool_definition: Dict[str, Any]) -> List[Dict[str, str]]:
    risks: List[Dict[str, str]] = []
    for path, text in iter_text_fragments(tool_definition):
        lower = text.lower()
        for pattern in PROMPT_RISK_PATTERNS:
            if pattern in lower:
                risks.append({"path": path, "pattern": pattern})
    return risks


def _extract_tools(tools_payload: Any) -> List[Dict[str, Any]]:
    if isinstance(tools_payload, dict):
        tools = tools_payload.get("tools", [])
    else:
        tools = tools_payload
    if not isinstance(tools, list):
        raise ValueError("MCP tools payload must be a list or object containing a tools list")
    return [tool for tool in tools if isinstance(tool, dict)]


def build_mcp_admission_manifest(
    tools_payload: Any,
    *,
    server_id: str,
    publisher: str = "",
    transport: str = "",
    server_url: Optional[str] = None,
    command: Optional[str] = None,
    args: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    tools = []
    for tool_definition in _extract_tools(tools_payload):
        name = str(tool_definition.get("name", ""))
        schema_hash = mcp_tool_schema_hash(tool_definition)
        tools.append(
            {
                "name": name,
                "schema_hash": schema_hash,
                "descriptor": canonical_mcp_tool_descriptor(tool_definition),
                "risks": detect_mcp_descriptor_risks(tool_definition),
            }
        )
    manifest = {
        "version": 1,
        "server_id": server_id,
        "publisher": publisher,
        "transport": transport,
        "server_url": server_url,
        "command": command,
        "args": list(args or []),
        "tools": tools,
    }
    manifest["server_hash"] = sha256_hex(
        canonical_json(
            {
                "server_id": server_id,
                "publisher": publisher,
                "transport": transport,
                "server_url": server_url,
                "command": command,
                "args": list(args or []),
                "tool_hashes": [tool["schema_hash"] for tool in tools],
            }
        )
    )
    return manifest


def get_mcp_servers(policy: Dict[str, Any]) -> Dict[str, Any]:
    direct = policy.get("mcp_servers")
    if isinstance(direct, dict):
        return direct
    nested = policy.get("mcp")
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        return nested["servers"]
    return {}


def _stdio_allowed_commands(policy: Optional[Dict[str, Any]], server_rule: Dict[str, Any]) -> List[str]:
    explicit = server_rule.get("allowed_commands")
    if isinstance(explicit, list) and explicit:
        return [str(item) for item in explicit]
    transport = (policy or {}).get("mcp_transport") or {}
    stdio = transport.get("stdio") if isinstance(transport, dict) else {}
    commands = stdio.get("allowed_commands") if isinstance(stdio, dict) else None
    if isinstance(commands, list) and commands:
        return [str(item) for item in commands]
    return list(DEFAULT_STDIO_COMMANDS)


def _contains_dangerous_token(text: str) -> bool:
    return any(token in text for token in STDIO_DANGEROUS_TOKENS)


def validate_mcp_server_config(server_rule: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> List[str]:
    """Validate transport-level MCP server configuration."""
    errors: List[str] = []
    transport = str(server_rule.get("transport", "")).lower()
    if not transport:
        return errors

    if transport == "stdio":
        if server_rule.get("shell") is True:
            errors.append("stdio MCP server must not run through a shell")
        if server_rule.get("allow_unsafe_command_execution") is True:
            errors.append("stdio MCP server enables unsafe command execution")
        command = str(server_rule.get("command", ""))
        if not command:
            errors.append("stdio MCP server missing command")
        elif _contains_dangerous_token(command) or any(ch.isspace() for ch in command):
            errors.append("stdio MCP command contains shell metacharacters or whitespace")
        else:
            allowed = _stdio_allowed_commands(policy, server_rule)
            command_name = Path(command).name
            if command_name not in allowed:
                errors.append(f"stdio MCP command '{command_name}' is not allowlisted")
        args = server_rule.get("args", [])
        if not isinstance(args, list):
            errors.append("stdio MCP args must be a list")
        else:
            for arg in args:
                arg_text = str(arg)
                if _contains_dangerous_token(arg_text):
                    errors.append("stdio MCP arg contains shell metacharacters")
                    break
    elif transport in {"http", "streamable-http", "sse"}:
        url = str(server_rule.get("url") or server_rule.get("server_url") or "")
        if url:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if parsed.scheme not in {"http", "https"}:
                errors.append("remote MCP server URL must use http or https")
            if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
                errors.append("remote MCP server must use https outside loopback development")
    else:
        errors.append(f"unsupported MCP transport '{transport}'")
    return errors


def verify_mcp_manifest_against_policy(manifest: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """Verify discovered MCP tools against policy-pinned server/tool metadata."""
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []
    server_id = str(manifest.get("server_id", ""))
    servers = get_mcp_servers(policy)
    server_rule = servers.get(server_id)
    if not isinstance(server_rule, dict):
        errors.append({"path": "server_id", "message": f"MCP server '{server_id}' is not approved"})
        return {"ok": False, "errors": errors, "warnings": warnings}
    if server_rule.get("enabled", True) is False:
        errors.append({"path": f"mcp_servers.{server_id}", "message": "MCP server is disabled"})

    transport = manifest.get("transport")
    if transport and server_rule.get("transport") and str(transport) != str(server_rule["transport"]):
        errors.append({"path": f"mcp_servers.{server_id}.transport", "message": "transport mismatch"})
    config_errors = validate_mcp_server_config({**server_rule, **{k: v for k, v in manifest.items() if v is not None}}, policy)
    for message in config_errors:
        errors.append({"path": f"mcp_servers.{server_id}", "message": message})

    approved_tools = server_rule.get("tools") or {}
    allow_unpinned = bool(server_rule.get("allow_unpinned_tools", False))
    for index, tool in enumerate(manifest.get("tools", [])):
        name = str(tool.get("name", ""))
        tool_rule = approved_tools.get(name)
        if not isinstance(tool_rule, dict):
            issue = {"path": f"tools[{index}].name", "message": f"MCP tool '{name}' is not pinned"}
            (warnings if allow_unpinned else errors).append(issue)
            continue
        expected_hash = tool_rule.get("schema_hash")
        actual_hash = tool.get("schema_hash")
        if not expected_hash:
            warnings.append({"path": f"mcp_servers.{server_id}.tools.{name}.schema_hash", "message": "tool is approved without schema pin"})
        elif expected_hash != actual_hash:
            errors.append({"path": f"tools[{index}].schema_hash", "message": f"MCP tool '{name}' schema hash mismatch"})
        risks = tool.get("risks") or []
        if risks and not tool_rule.get("allow_poison_risks", False):
            errors.append({"path": f"tools[{index}].risks", "message": f"MCP tool '{name}' contains prompt-like schema text"})
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def analyze_tool_output(output: Any, policy: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """Flag tool outputs that appear to instruct follow-up sensitive actions."""
    patterns = list(OUTPUT_REQUEST_PATTERNS)
    extra = (policy or {}).get("tool_output_risk_patterns")
    if isinstance(extra, list):
        patterns.extend(str(item) for item in extra)
    risks: List[Dict[str, str]] = []
    for path, text in iter_text_fragments(output):
        lower = text.lower()
        for pattern in patterns:
            if pattern in lower:
                risks.append({"path": path, "pattern": pattern})
    return risks


def find_sensitive_payload(value: Any, policy: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    patterns = list(SENSITIVE_PAYLOAD_PATTERNS)
    extra = (policy or {}).get("sensitive_payload_patterns")
    if isinstance(extra, list):
        patterns.extend(str(item) for item in extra)
    findings: List[Dict[str, str]] = []
    for path, text in iter_text_fragments(value):
        lower = text.lower()
        for pattern in patterns:
            if pattern in lower:
                findings.append({"path": path, "pattern": pattern})
    return findings


def _server_trust_tier(policy: Dict[str, Any], server_id: str) -> str:
    rule = get_mcp_servers(policy).get(server_id) or {}
    return str(rule.get("trust_tier", "untrusted")).lower()


def _flow_edges(policy: Dict[str, Any], key: str) -> List[Tuple[str, str]]:
    flows = policy.get("mcp_data_flows") or {}
    edges = flows.get(key, []) if isinstance(flows, dict) else []
    result: List[Tuple[str, str]] = []
    if isinstance(edges, list):
        for edge in edges:
            if isinstance(edge, dict) and "from" in edge and "to" in edge:
                result.append((str(edge["from"]), str(edge["to"])))
    return result


def check_mcp_data_flow(policy: Dict[str, Any], *, source_servers: Sequence[str], target_server: str) -> Tuple[bool, str]:
    """Enforce cross-server MCP data-flow policy."""
    if not source_servers:
        return True, "no cross-server data origins declared"
    allowed = set(_flow_edges(policy, "allowed"))
    blocked = set(_flow_edges(policy, "blocked"))
    target_tier = _server_trust_tier(policy, target_server)
    for source in source_servers:
        if source == target_server:
            continue
        edge = (source, target_server)
        if edge in blocked:
            return False, f"MCP data flow {source}->{target_server} is blocked"
        if edge in allowed:
            continue
        if target_tier in {"third-party", "untrusted", "external"}:
            return False, f"MCP data flow {source}->{target_server} requires an explicit allow rule"
    return True, "MCP data flow permitted"
