"""Issue a local development capability ticket via prompt-sentinel-core."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import _core_loader  # noqa: F401
from prompt_sentinel.core.runtime import issue_capability


KEY_DIR = Path.cwd() / ".prompt_sentinel"
PRIVATE_KEY = KEY_DIR / "codex-dev.ed25519"
PUBLIC_KEY = KEY_DIR / "codex-dev.ed25519.pub"


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: request_capability.py <authority> <audience> <operation> <scope.json> <params.json>",
            file=sys.stderr,
        )
        return 2
    authority, audience, operation, scope, params = sys.argv[1:]
    session_id = "codex-session"
    ticket = issue_capability(
        authority=authority,
        audience=audience,
        operation=operation,
        session_id=session_id,
        scope=json.loads(Path(scope).read_text(encoding="utf-8")),
        params=json.loads(Path(params).read_text(encoding="utf-8")),
        private_key_path=PRIVATE_KEY,
        public_key_path=PUBLIC_KEY,
        key_id="codex-dev-key",
    )
    print(json.dumps(ticket.__dict__, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
