"""Issue a local development capability ticket via the local Prompt_Sentinel core."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import _core_loader  # noqa: F401
from prompt_sentinel.core.runtime import issue_capability


KEY_DIR = Path.cwd() / ".prompt_sentinel"
PRIVATE_KEY = KEY_DIR / "codex-dev.ed25519"
PUBLIC_KEY = KEY_DIR / "codex-dev.ed25519.pub"
DEFAULT_SESSION_ID = "codex-session"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a local development capability ticket for Prompt_Sentinel."
    )
    parser.add_argument("authority", help="Authority name to embed in the ticket")
    parser.add_argument("audience", help="Expected audience for the ticket")
    parser.add_argument("operation", help="Approved operation for the ticket")
    parser.add_argument("scope", type=Path, help="Path to a JSON scope document")
    parser.add_argument("params", type=Path, help="Path to a JSON params document")
    parser.add_argument(
        "--session-id",
        default=DEFAULT_SESSION_ID,
        help="Session identifier to bind into the ticket. Defaults to codex-session.",
    )
    parser.add_argument(
        "--private-key",
        type=Path,
        default=PRIVATE_KEY,
        help="Optional private-key path for local-dev issuance.",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=PUBLIC_KEY,
        help="Optional public-key output path for local-dev issuance.",
    )
    parser.add_argument(
        "--key-id",
        default="codex-dev-key",
        help="Key identifier to embed in the issued ticket.",
    )
    args = parser.parse_args()

    ticket = issue_capability(
        authority=args.authority,
        audience=args.audience,
        operation=args.operation,
        session_id=args.session_id,
        scope=json.loads(args.scope.read_text(encoding="utf-8")),
        params=json.loads(args.params.read_text(encoding="utf-8")),
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        key_id=args.key_id,
    )
    print(json.dumps(ticket.__dict__, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
