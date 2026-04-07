"""Shared helpers for Claude hook scripts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict


ALERT_PATH = Path(".claude/prompt-sentinel.alerts.jsonl")
AUDIT_PATH = Path(".claude/prompt-sentinel.audit.jsonl")

# Resolve the package root (prompt-sentinel-claude/) from hooks/common.py
_PACKAGE_ROOT = Path(__file__).resolve().parents[1]

# Core runtime is now bundled inside the package root
CORE_SRC = _PACKAGE_ROOT / "prompt-sentinel-core" / "src"

# Policy lookup: project-local override > package-bundled claude policy > core default policy
BUNDLED_POLICY_PATH = _PACKAGE_ROOT / "policies" / "claude-default-policy.json"
CORE_POLICY_PATH = _PACKAGE_ROOT / "prompt-sentinel-core" / "src" / "prompt_sentinel" / "policies" / "default-policy.json"
LOCAL_POLICY_PATH = Path(".claude/prompt-sentinel.policy.json")
LOCAL_MANIFEST_PATH = Path(".claude/prompt-sentinel.manifest.json")

if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from prompt_sentinel.core.detection import detect_prompt_patterns, detect_tool_text  # noqa: E402
from prompt_sentinel.core.manifests import InstructionManifest  # noqa: E402
from prompt_sentinel.core.runtime import evaluate_proposal  # noqa: E402


def read_event() -> dict:
    return json.load(sys.stdin)


def write_response(payload: dict) -> None:
    print(json.dumps({"hookSpecificOutput": payload}, ensure_ascii=False))


def append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def emit_alert(payload: dict) -> None:
    append_jsonl(ALERT_PATH, payload)


def resolve_policy_path() -> Path:
    if LOCAL_POLICY_PATH.exists():
        return LOCAL_POLICY_PATH
    if BUNDLED_POLICY_PATH.exists():
        return BUNDLED_POLICY_PATH
    if CORE_POLICY_PATH.exists():
        return CORE_POLICY_PATH
    # Fall back to bundled path and let downstream raise if missing
    return BUNDLED_POLICY_PATH


def normalize_tool_proposal(event: Dict[str, Any]) -> Dict[str, Any]:
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    if isinstance(tool_input, dict):
        params = dict(tool_input)
    else:
        params = {"input": str(tool_input)}
    if tool_name == "Bash" and "command" not in params:
        for key in ("cmd", "input"):
            if key in params:
                params["command"] = params[key]
                break
    return {"tool": tool_name, "params": params}


def verify_manifest_if_present() -> Dict[str, Dict[str, str]]:
    if not LOCAL_MANIFEST_PATH.exists():
        return {}
    manifest = json.loads(LOCAL_MANIFEST_PATH.read_text(encoding="utf-8"))
    return InstructionManifest.verify(manifest)


def evaluate_hook_proposal(event: Dict[str, Any]):
    return evaluate_proposal(
        policy_path=resolve_policy_path(),
        proposal_data=normalize_tool_proposal(event),
        audit_log_path=AUDIT_PATH,
        base_dir=Path(event.get("cwd") or Path.cwd()),
        session_id=event.get("session_id"),
        user_id="claude-user",
        role="agent",
        tenant="local",
    )
