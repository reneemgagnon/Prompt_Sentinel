from prompt_sentinel.core.validation import validate_policy


def test_validate_policy_accepts_tiered_metadata() -> None:
    policy = {
        "tool_permissions": {
            "file_read": {
                "allowed_params": ["path"],
                "path_whitelist": ["workspace/*"],
                "max_calls_per_session": 5,
                "retention_class": "security-audit",
                "sensitive_action_class": "restricted",
                "approval_scope": "repo-boundary",
            }
        },
        "capability_required_tools": [],
        "inheritance": {"extends": ["developer-default"]},
        "meta": {"policy_name": "guard-team"},
    }
    result = validate_policy(policy)
    assert result.ok is True
    assert result.errors == []


def test_validate_policy_rejects_unknown_capability_tool() -> None:
    policy = {
        "tool_permissions": {
            "echo": {
                "allowed_params": ["message"],
                "max_calls_per_session": 5,
            }
        },
        "capability_required_tools": ["sensitive_export"],
    }
    result = validate_policy(policy)
    assert result.ok is False
    assert any("unknown tools" in issue.message for issue in result.errors)