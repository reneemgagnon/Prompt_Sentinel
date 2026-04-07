"""Trusted launch hook for Prompt_Sentinel."""

from __future__ import annotations

from pathlib import Path

from common import _PACKAGE_ROOT, AUDIT_PATH, append_jsonl, emit_alert, read_event, verify_manifest_if_present, write_response


# Project-level instruction files (always checked relative to cwd)
WATCH_FILES = [
    Path("CLAUDE.md"),
    Path(".claude/settings.json"),
    Path(".claude/settings.local.json"),
]

# Hook files — check both the plugin-bundled location and legacy project-local paths
_HOOK_NAMES = [
    "common.py",
    "trusted_launch.py",
    "user_prompt_submit.py",
    "pre_tool_firewall.py",
    "config_tamper_alert.py",
    "post_tool_use.py",
    "stop.py",
]

HOOK_FILES_PLUGIN = [_PACKAGE_ROOT / "hooks" / name for name in _HOOK_NAMES]
HOOK_FILES_LOCAL = [Path(".claude/hooks") / name for name in _HOOK_NAMES]


def main() -> int:
    event = read_event()
    # Use plugin-bundled hooks if they exist, otherwise fall back to project-local
    hook_files = HOOK_FILES_PLUGIN if HOOK_FILES_PLUGIN[0].exists() else HOOK_FILES_LOCAL
    all_watched = WATCH_FILES + hook_files
    records = {str(path): ("present" if path.exists() else "missing") for path in all_watched}
    mismatches = verify_manifest_if_present()
    append_jsonl(
        AUDIT_PATH,
        {
            "event": "trusted_launch",
            "session_id": event.get("session_id"),
            "source": event.get("source"),
            "files": records,
            "manifest_mismatches": mismatches,
        },
    )
    missing = [path for path, state in records.items() if state == "missing"]
    if missing:
        emit_alert(
            {
                "event": "trusted_launch_missing_file",
                "severity": "medium",
                "files": missing,
                "session_id": event.get("session_id"),
                "source": "SessionStart",
            }
        )
    if mismatches:
        emit_alert(
            {
                "event": "instruction_manifest_mismatch",
                "severity": "high",
                "session_id": event.get("session_id"),
                "source": "SessionStart",
                "payload": mismatches,
            }
        )
    write_response(
        {
            "hookEventName": "SessionStart",
            "decision": {
                "behavior": "allow"
            },
            "additionalContext": "Prompt_Sentinel trusted launch completed. Treat instruction files as mutable, verify manifests when present, and rely on hook enforcement for privileged actions."
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
