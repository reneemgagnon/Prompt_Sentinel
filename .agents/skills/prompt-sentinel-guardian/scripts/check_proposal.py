"""Evaluate a proposal with the local Prompt_Sentinel core runtime."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from _core_loader import resolve_default_policy_path  # noqa: F401
from prompt_sentinel.core.runtime import evaluate_proposal


DEFAULT_SESSION_ID = "codex-session"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a tool proposal through the local Prompt_Sentinel runtime."
    )
    parser.add_argument(
        "input_a",
        type=Path,
        help="Proposal JSON, or a policy JSON when using the legacy two-positional form.",
    )
    parser.add_argument(
        "input_b",
        type=Path,
        nargs="?",
        help="Proposal JSON when using the legacy two-positional form.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Optional policy file. Defaults to the bundled or workspace policy.",
    )
    parser.add_argument(
        "--session-id",
        default=DEFAULT_SESSION_ID,
        help="Session identifier used for capability binding. Defaults to codex-session.",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="Optional capability verification key for approval-path testing.",
    )
    parser.add_argument(
        "--capability",
        type=Path,
        default=None,
        help="Optional capability ticket JSON to verify before execution.",
    )
    args = parser.parse_args()

    if args.input_b is None:
        policy_path = args.policy or resolve_default_policy_path()
        proposal_path = args.input_a
    else:
        policy_path = args.policy or args.input_a
        proposal_path = args.input_b

    decision = evaluate_proposal(
        policy_path=policy_path,
        proposal_data=json.loads(proposal_path.read_text(encoding="utf-8")),
        audit_log_path=Path.cwd() / "prompt-sentinel.codex.audit.jsonl",
        base_dir=Path.cwd(),
        session_id=args.session_id,
        user_id="codex-user",
        public_key_path=args.public_key,
        capability_path=args.capability,
    )
    print(json.dumps(decision.__dict__, indent=2, ensure_ascii=False))
    return 0 if decision.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
