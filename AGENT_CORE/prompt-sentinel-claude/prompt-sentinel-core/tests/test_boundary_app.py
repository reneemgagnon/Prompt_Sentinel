"""Tests for BoundaryApp — end-to-end proposal handling."""

from pathlib import Path

from prompt_sentinel.core.audit import AuditChain
from prompt_sentinel.core.boundary_app import BoundaryApp
from prompt_sentinel.core.capability import CapabilityService
from prompt_sentinel.core.enforcer import PolicyEnforcer
from prompt_sentinel.core.models import SessionFacts, ToolProposal
from prompt_sentinel.core.tool_registry import ToolRegistry


POLICY = {
    "tool_permissions": {
        "echo": {"allowed_params": ["message"], "max_calls_per_session": 10},
        "sensitive_export": {"allowed_params": ["dataset", "format"], "max_calls_per_session": 5},
    },
    "capability_required_tools": ["sensitive_export"],
}

SESSION = SessionFacts(session_id="test-session", user_id="tester")


def _app(tmp_path: Path, *, with_capability_service: bool = False) -> BoundaryApp:
    reg = ToolRegistry(base_dir=tmp_path)
    cap_svc = None
    if with_capability_service:
        key = CapabilityService.generate_private_key()
        cap_svc = CapabilityService(
            private_key=key,
            public_key=key.public_key(),
            expected_audience="test.audience",
        )
    return BoundaryApp(
        enforcer=PolicyEnforcer(POLICY),
        tools=reg,
        audit=AuditChain(tmp_path / "audit.jsonl"),
        capability_service=cap_svc,
    )


def test_allowed_proposal(tmp_path: Path):
    app = _app(tmp_path)
    decision = app.handle(
        session=SESSION,
        proposal=ToolProposal(tool="echo", params={"message": "hi"}),
    )
    assert decision.allowed is True
    assert decision.result == {"echo": {"message": "hi"}}


def test_denied_unknown_tool(tmp_path: Path):
    app = _app(tmp_path)
    decision = app.handle(
        session=SESSION,
        proposal=ToolProposal(tool="drop_database", params={}),
    )
    assert decision.allowed is False
    assert "not allowed" in decision.reason


def test_capability_required_without_ticket(tmp_path: Path):
    app = _app(tmp_path, with_capability_service=True)
    decision = app.handle(
        session=SESSION,
        proposal=ToolProposal(tool="sensitive_export", params={"dataset": "users", "format": "csv"}),
    )
    assert decision.allowed is False
    assert decision.capability_required is True
    assert "not provided" in decision.reason


def test_capability_required_with_valid_ticket(tmp_path: Path):
    app = _app(tmp_path, with_capability_service=True)
    params = {"dataset": "users", "format": "csv"}
    ticket = app.capability_service.issue(
        key_id="k1",
        authority="policy_engine",
        audience="test.audience",
        operation="approve_tool_call",
        session_id="test-session",
        scope={"tool": "sensitive_export"},
        params=params,
    )
    decision = app.handle(
        session=SESSION,
        proposal=ToolProposal(tool="sensitive_export", params=params),
        capability=ticket,
    )
    assert decision.allowed is True


def test_capability_required_with_wrong_session_ticket(tmp_path: Path):
    app = _app(tmp_path, with_capability_service=True)
    params = {"dataset": "users", "format": "csv"}
    ticket = app.capability_service.issue(
        key_id="k1",
        authority="policy_engine",
        audience="test.audience",
        operation="approve_tool_call",
        session_id="wrong-session",
        scope={"tool": "sensitive_export"},
        params=params,
    )
    decision = app.handle(
        session=SESSION,
        proposal=ToolProposal(tool="sensitive_export", params=params),
        capability=ticket,
    )
    assert decision.allowed is False
    assert "invalid capability" in decision.reason


def test_audit_entries_written(tmp_path: Path):
    app = _app(tmp_path)
    app.handle(session=SESSION, proposal=ToolProposal(tool="echo", params={"message": "a"}))
    app.handle(session=SESSION, proposal=ToolProposal(tool="bad_tool", params={}))
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
