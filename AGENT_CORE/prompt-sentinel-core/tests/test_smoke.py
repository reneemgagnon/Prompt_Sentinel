from pathlib import Path

from prompt_sentinel.core.audit import AuditChain
from prompt_sentinel.core.boundary_app import BoundaryApp
from prompt_sentinel.core.enforcer import PolicyEnforcer
from prompt_sentinel.core.models import SessionFacts, ToolProposal
from prompt_sentinel.core.tool_registry import ToolRegistry


def test_boundary_allows_simple_echo(tmp_path: Path) -> None:
    policy = {
        "tool_permissions": {
            "echo": {
                "allowed_params": ["message"],
                "max_calls_per_session": 5,
            }
        }
    }
    registry = ToolRegistry(base_dir=tmp_path)
    registry.register("echo", lambda params: {"echo": params["message"]})
    app = BoundaryApp(
        enforcer=PolicyEnforcer(policy),
        tools=registry,
        audit=AuditChain(tmp_path / "audit.jsonl"),
    )
    decision = app.handle(
        session=SessionFacts(session_id="s1", user_id="u1"),
        proposal=ToolProposal(tool="echo", params={"message": "hi"}),
    )
    assert decision.allowed is True
    assert decision.result == {"echo": "hi"}
