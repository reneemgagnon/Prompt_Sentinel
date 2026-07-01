import json
import sys
from pathlib import Path

from prompt_sentinel.cli.main import main
from prompt_sentinel.core.runtime import ensure_keypair, issue_capability


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_policy_validate_command_ok(tmp_path: Path, monkeypatch, capsys) -> None:
    policy = tmp_path / "policy.json"
    _write_json(
        policy,
        {
            "tool_permissions": {
                "echo": {
                    "allowed_params": ["message"],
                    "max_calls_per_session": 5,
                }
            },
            "capability_required_tools": [],
        },
    )
    monkeypatch.setattr(sys, "argv", ["prompt-sentinel", "policy", "validate", "--policy", str(policy)])
    code = main()
    assert code == 0
    captured = capsys.readouterr()
    assert '"ok": true' in captured.out.lower()


def test_verify_capability_command_ok(tmp_path: Path, monkeypatch, capsys) -> None:
    params = {"message": "hello"}
    params_path = tmp_path / "params.json"
    scope_path = tmp_path / "scope.json"
    ticket_path = tmp_path / "ticket.json"
    private_key_path = tmp_path / "dev.key"
    public_key_path = tmp_path / "dev.key.pub"

    _write_json(params_path, params)
    _write_json(scope_path, {"tool": "echo"})
    ensure_keypair(private_key_path, public_key_path)
    ticket = issue_capability(
        authority="policy_engine",
        audience="local.prompt-sentinel",
        operation="approve_tool_call",
        session_id="sess-1",
        scope={"tool": "echo"},
        params=params,
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        key_id="dev-key",
    )
    ticket_path.write_text(json.dumps(ticket.__dict__), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prompt-sentinel",
            "verify-capability",
            "--capability",
            str(ticket_path),
            "--public-key",
            str(public_key_path),
            "--params",
            str(params_path),
            "--session-id",
            "sess-1",
        ],
    )
    code = main()
    assert code == 0
    captured = capsys.readouterr()
    assert '"ok": true' in captured.out.lower()


def test_audit_tail_command_filters_records(tmp_path: Path, monkeypatch, capsys) -> None:
    audit_log = tmp_path / "audit.jsonl"
    records = [
        {"event": "tool_call_allowed", "tool": "echo", "timestamp": 1000},
        {"event": "tool_call_denied", "tool": "file_read", "timestamp": 1001},
    ]
    audit_log.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prompt-sentinel",
            "audit",
            "tail",
            "--audit-log",
            str(audit_log),
            "--event",
            "tool_call_denied",
        ],
    )
    code = main()
    assert code == 0
    captured = capsys.readouterr()
    assert '"count": 1' in captured.out.lower()
    assert 'file_read' in captured.out