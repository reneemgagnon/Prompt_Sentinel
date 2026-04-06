"""Command-line entry points for Prompt_Sentinel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from prompt_sentinel.core.exporters import export_audit_log
from prompt_sentinel.core.policy_vault import PolicyVault
from prompt_sentinel.core.runtime import evaluate_proposal, issue_capability, load_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prompt-sentinel")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check-proposal", help="Evaluate a tool proposal against a policy")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--proposal", type=Path, required=True)
    check.add_argument("--audit-log", type=Path, default=Path("prompt_sentinel.audit.jsonl"))
    check.add_argument("--base-dir", type=Path, default=Path.cwd())
    check.add_argument("--session-id", default=None)
    check.add_argument("--user-id", default="local-user")
    check.add_argument("--role", default="developer")
    check.add_argument("--tenant", default="default")
    check.add_argument("--public-key", type=Path)
    check.add_argument("--capability", type=Path)
    check.add_argument("--audience", default="local.prompt-sentinel")

    summary = subparsers.add_parser("policy-summary", help="Emit the safe summary for a policy")
    summary.add_argument("--policy", type=Path, required=True)

    issue = subparsers.add_parser("issue-capability", help="Issue a local capability ticket")
    issue.add_argument("--authority", required=True)
    issue.add_argument("--audience", required=True)
    issue.add_argument("--operation", required=True)
    issue.add_argument("--session-id", required=True)
    issue.add_argument("--scope", type=Path, required=True)
    issue.add_argument("--params", type=Path, required=True)
    issue.add_argument("--private-key", type=Path, required=True)
    issue.add_argument("--public-key", type=Path)
    issue.add_argument("--key-id", default="local-dev-key")

    export = subparsers.add_parser("audit-export", help="Export audit log to a sink")
    export.add_argument("--audit-log", type=Path, default=Path("prompt_sentinel.audit.jsonl"))
    export.add_argument("--destination", required=True, help="Export URI: file://, https://, s3://, or stdout")
    export.add_argument("--after", type=int, default=None, help="Only export entries after this Unix timestamp")
    export.add_argument("--header", action="append", default=[], help="HTTP header as Key:Value (for webhook)")

    return parser


def cmd_check_proposal(args: argparse.Namespace) -> int:
    proposal_json = load_json(args.proposal)
    decision = evaluate_proposal(
        policy_path=args.policy,
        proposal_data=proposal_json,
        audit_log_path=args.audit_log,
        base_dir=args.base_dir,
        session_id=args.session_id,
        user_id=args.user_id,
        role=args.role,
        tenant=args.tenant,
        public_key_path=args.public_key,
        expected_audience=args.audience,
        capability_path=args.capability,
    )
    print(json.dumps(decision.__dict__, indent=2, ensure_ascii=False))
    return 0 if decision.allowed else 2


def cmd_policy_summary(args: argparse.Namespace) -> int:
    policy = load_json(args.policy)
    print(json.dumps(PolicyVault.safe_summary(policy), indent=2, ensure_ascii=False))
    return 0


def cmd_issue_capability(args: argparse.Namespace) -> int:
    scope = load_json(args.scope)
    params = load_json(args.params)
    ticket = issue_capability(
        authority=args.authority,
        audience=args.audience,
        operation=args.operation,
        session_id=args.session_id,
        scope=scope,
        params=params,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        key_id=args.key_id,
    )
    print(json.dumps(ticket.__dict__, indent=2, ensure_ascii=False))
    return 0


def cmd_audit_export(args: argparse.Namespace) -> int:
    headers = {}
    for h in args.header:
        key, _, value = h.partition(":")
        headers[key.strip()] = value.strip()
    kwargs = {}
    if headers:
        kwargs["headers"] = headers
    result = export_audit_log(
        args.audit_log,
        args.destination,
        after_timestamp=args.after,
        **kwargs,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "check-proposal":
        return cmd_check_proposal(args)
    if args.command == "policy-summary":
        return cmd_policy_summary(args)
    if args.command == "issue-capability":
        return cmd_issue_capability(args)
    if args.command == "audit-export":
        return cmd_audit_export(args)
    parser.error(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
