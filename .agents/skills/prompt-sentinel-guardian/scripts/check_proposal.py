"""Evaluate a proposal with the local prompt-sentinel-core runtime."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import _core_loader  # noqa: F401
from prompt_sentinel.core.runtime import evaluate_proposal


DEFAULT_POLICY = Path(__file__).resolve().parents[4] / "AGENT_CORE" / "prompt-sentinel-codex" / "policies" / "codex-default-policy.json"


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: check_proposal.py [<policy.json>] <proposal.json>", file=sys.stderr)
        return 2
    if len(sys.argv) == 2:
        policy = DEFAULT_POLICY
        proposal = Path(sys.argv[1])
    else:
        policy = Path(sys.argv[1])
        proposal = Path(sys.argv[2])
    decision = evaluate_proposal(
        policy_path=policy,
        proposal_data=json.loads(proposal.read_text(encoding="utf-8")),
        audit_log_path=Path.cwd() / "prompt-sentinel.codex.audit.jsonl",
        base_dir=Path.cwd(),
        user_id="codex-user",
    )
    print(json.dumps(decision.__dict__, indent=2, ensure_ascii=False))
    return 0 if decision.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
