"""PreToolUse firewall hook for Prompt_Sentinel."""

from __future__ import annotations

from common import detect_tool_text, emit_alert, evaluate_hook_proposal, read_event, write_response


def main() -> int:
    event = read_event()
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    text = " ".join(str(value) for value in tool_input.values()) if isinstance(tool_input, dict) else str(tool_input)
    matches = detect_tool_text(text)

    decision = evaluate_hook_proposal(event)
    if not decision.allowed:
        emit_alert(
            {
                "event": "pre_tool_policy_denial",
                "severity": "high",
                "session_id": event.get("session_id"),
                "tool_name": tool_name,
                "source": "PreToolUse",
                "payload": {"reason": decision.reason},
            }
        )
        write_response(
            {
                "hookEventName": "PreToolUse",
                "decision": {
                    "behavior": "deny",
                    "reason": f"Prompt_Sentinel denied {tool_name}: {decision.reason}"
                }
            }
        )
        return 0

    if matches["block"]:
        emit_alert(
            {
                "event": "pre_tool_block",
                "severity": "high",
                "session_id": event.get("session_id"),
                "tool_name": tool_name,
                "source": "PreToolUse",
                "payload": {"patterns": matches["block"]},
            }
        )
        write_response(
            {
                "hookEventName": "PreToolUse",
                "decision": {
                    "behavior": "deny",
                    "reason": f"Prompt_Sentinel blocked {tool_name}: matched protected pattern(s) {matches['block']}."
                }
            }
        )
        return 0

    if decision.capability_required or matches["ask"]:
        emit_alert(
            {
                "event": "pre_tool_requires_review",
                "severity": "medium",
                "session_id": event.get("session_id"),
                "tool_name": tool_name,
                "source": "PreToolUse",
                "payload": {
                    "patterns": matches["ask"],
                    "capability_required": decision.capability_required,
                },
            }
        )
        reason = decision.capability_reason if decision.capability_required else f"matched review pattern(s) {matches['ask']}"
        write_response(
            {
                "hookEventName": "PreToolUse",
                "decision": {
                    "behavior": "ask",
                    "reason": f"Prompt_Sentinel flagged {tool_name} for review: {reason}."
                }
            }
        )
        return 0

    write_response(
        {
            "hookEventName": "PreToolUse",
            "decision": {
                "behavior": "allow"
            }
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
