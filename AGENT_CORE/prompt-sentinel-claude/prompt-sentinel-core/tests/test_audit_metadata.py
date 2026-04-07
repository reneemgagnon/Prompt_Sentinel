import json
from pathlib import Path

from prompt_sentinel.core.audit import AuditChain
from prompt_sentinel.core.boundary_app import BoundaryApp
from prompt_sentinel.core.capability import CapabilityService
from prompt_sentinel.core.enforcer import PolicyEnforcer
from prompt_sentinel.core.models import SessionFacts, ToolProposal
from prompt_sentinel.core.tool_registry import ToolRegistry


def test_boundary_app_emits_rich_audit_metadata(tmp_path: Path) -> None:
    policy = {
        "tool_permissions": {
            "echo": {
                "allowed_params": ["message"],
                "max_calls_per_session": 5,
                "retention_class": "security-audit",
                "sensitive_action_class": "restricted",
            }
        },
        "capability_required_tools": [],
        "meta": {"policy_name": "guard-team"},
    }
    key = CapabilityService.generate_private_key()
    capability_service = CapabilityService(
        private_key=key,
        public_key=key.public_key(),
        expected_audience="test.audience",
    )
    app = BoundaryApp(
        enforcer=PolicyEnforcer(policy),
        tools=ToolRegistry(base_dir=tmp_path),
        audit=AuditChain(tmp_path / "audit.jsonl"),
        capability_service=capability_service,
    )
    params = {"message": "hi"}
    capability = capability_service.issue(
        key_id="k1",
        authority="policy_engine",
        audience="test.audience",
        operation="approve_tool_call",
        session_id="s1",
        scope={"tool": "echo"},
        params=params,
    )
    decision = app.handle(
        session=SessionFacts(session_id="s1", user_id="u1"),
        proposal=ToolProposal(tool="echo", params=params),
        capability=capability,
    )
    assert decision.allowed is True
    assert decision.metadata["policy_name"] == "guard-team"
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    record = json.loads(lines[-1])
    assert record["policy_result"] == "allowed"
    assert record["retention_class"] == "security-audit"
    assert record["sensitive_action_class"] == "restricted"
    assert record["capability_status"] == "valid"
    assert record["params_hash"]