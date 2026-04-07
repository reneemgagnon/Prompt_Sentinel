"""Generate or verify instruction manifests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from prompt_sentinel.core.manifests import InstructionManifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="instruction-manifest")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("paths", nargs="+")
    create.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "create":
        manifest = InstructionManifest.build(Path(path) for path in args.paths)
        args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(args.output)
        return 0
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    mismatches = InstructionManifest.verify(manifest)
    print(json.dumps(mismatches, indent=2))
    return 0 if not mismatches else 2


if __name__ == "__main__":
    raise SystemExit(main())
