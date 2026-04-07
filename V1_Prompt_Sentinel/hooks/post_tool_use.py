"""Starter PostToolUse hook for Prompt_Sentinel."""

from __future__ import annotations

from common import AUDIT_PATH, append_jsonl, read_event, write_response


def main() -> int:
    event = read_event()
    append_jsonl(
        AUDIT_PATH,
        {
            "event": "PostToolUse",
            "tool_name": event.get("tool_name"),
            "session_id": event.get("session_id"),
        },
    )
    write_response(
        {
            "hookEventName": "PostToolUse",
            "decision": {
                "behavior": "allow"
            }
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
