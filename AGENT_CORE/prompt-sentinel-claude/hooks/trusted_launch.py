"""Trusted launch hook for Prompt_Sentinel."""

from __future__ import annotations

from pathlib import Path

from common import AUDIT_PATH, append_jsonl, emit_alert, read_event, verify_manifest_if_present, write_response


WATCH_FILES = [
    Path("CLAUDE.md"),
    Path(".claude/settings.json"),
    Path(".claude/settings.local.json"),
]

HOOK_FILES = [
    Path(".claude/hooks/common.py"),
    Path(".claude/hooks/trusted_launch.py"),
    Path(".claude/hooks/user_prompt_submit.py"),
    Path(".claude/hooks/pre_tool_firewall.py"),
    Path(".claude/hooks/config_tamper_alert.py"),
    Path(".claude/hooks/post_tool_use.py"),
    Path(".claude/hooks/stop.py"),
]


def main() -> int:
    event = read_event()
    all_watched = WATCH_FILES + HOOK_FILES
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
