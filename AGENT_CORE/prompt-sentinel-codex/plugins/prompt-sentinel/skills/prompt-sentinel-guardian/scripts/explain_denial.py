"""Turn a structured denial into user-facing language."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: explain_denial.py <decision.json>", file=sys.stderr)
        return 2
    decision = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    tool = decision.get("tool", "tool")
    reason = decision.get("reason", "blocked by policy")
    capability_required = bool(decision.get("capability_required"))
    guidance = f"The proposed {tool} action was blocked: {reason}."
    if capability_required:
        guidance += " This path appears to require a signed capability or human approval."
    guidance += " Suggest a lower-privilege alternative or ask for approval."
    print(guidance)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
