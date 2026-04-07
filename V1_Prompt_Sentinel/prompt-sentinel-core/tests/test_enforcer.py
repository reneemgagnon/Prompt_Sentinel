"""Tests for PolicyEnforcer."""

from prompt_sentinel.core.enforcer import PolicyEnforcer
from prompt_sentinel.core.models import SessionFacts


POLICY = {
    "tool_permissions": {
        "echo": {
            "allowed_params": ["message"],
            "max_calls_per_session": 3,
        },
        "file_read": {
            "allowed_params": ["path"],
            "path_whitelist": ["workspace/*", "docs/*"],
            "max_calls_per_session": 5,
        },
        "sensitive_export": {
            "allowed_params": ["dataset", "format"],
            "max_calls_per_session": 1,
        },
    },
    "capability_required_tools": ["sensitive_export"],
}

SESSION = SessionFacts(session_id="test-session", user_id="tester")


def _enforcer() -> PolicyEnforcer:
    return PolicyEnforcer(POLICY)


# ── Tool whitelist ──────────────────────────────────────────────────
def test_allowed_tool():
    ok, reason = _enforcer().check_tool_call(session=SESSION, tool="echo", params={"message": "hi"})
    assert ok is True
    assert "permitted" in reason


def test_unknown_tool_denied():
    ok, reason = _enforcer().check_tool_call(session=SESSION, tool="rm_rf", params={})
    assert ok is False
    assert "not allowed" in reason


# ── Param validation ────────────────────────────────────────────────
def test_unknown_param_denied():
    ok, reason = _enforcer().check_tool_call(session=SESSION, tool="echo", params={"message": "hi", "evil": "x"})
    assert ok is False
    assert "unknown params" in reason


# ── Path whitelist ──────────────────────────────────────────────────
def test_path_whitelist_allows():
    ok, _ = _enforcer().check_tool_call(session=SESSION, tool="file_read", params={"path": "workspace/main.py"})
    assert ok is True


def test_path_whitelist_blocks():
    ok, reason = _enforcer().check_tool_call(session=SESSION, tool="file_read", params={"path": "/etc/passwd"})
    assert ok is False
    assert "not allowlisted" in reason


def test_path_whitelist_missing_path():
    ok, reason = _enforcer().check_tool_call(session=SESSION, tool="file_read", params={})
    assert ok is False
    assert "missing" in reason


# ── Call quotas ─────────────────────────────────────────────────────
def test_quota_enforcement():
    enforcer = _enforcer()
    for _ in range(3):
        ok, _ = enforcer.check_tool_call(session=SESSION, tool="echo", params={"message": "x"})
        assert ok is True
    ok, reason = enforcer.check_tool_call(session=SESSION, tool="echo", params={"message": "x"})
    assert ok is False
    assert "quota exceeded" in reason


def test_quota_is_per_session():
    enforcer = _enforcer()
    s1 = SessionFacts(session_id="s1", user_id="u1")
    s2 = SessionFacts(session_id="s2", user_id="u1")
    for _ in range(3):
        enforcer.check_tool_call(session=s1, tool="echo", params={"message": "x"})
    ok, _ = enforcer.check_tool_call(session=s2, tool="echo", params={"message": "x"})
    assert ok is True


# ── Capability required ─────────────────────────────────────────────
def test_capability_required_by_tool():
    required, reason = _enforcer().capability_required(tool="sensitive_export", params={})
    assert required is True
    assert "tool classification" in reason


def test_capability_not_required():
    required, _ = _enforcer().capability_required(tool="echo", params={})
    assert required is False


def test_capability_required_by_path_heuristic():
    required, reason = _enforcer().capability_required(tool="file_read", params={"path": "data/secret_keys.txt"})
    assert required is True
    assert "sensitive path" in reason
