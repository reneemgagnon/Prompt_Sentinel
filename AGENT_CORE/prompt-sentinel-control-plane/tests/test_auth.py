"""Tests for bearer-token authentication."""

from prompt_sentinel_control_plane.auth import TokenAuth


def test_disabled_when_no_tokens():
    auth = TokenAuth(tokens=[])
    assert auth.enabled is False
    assert auth.verify("anything") is True


def test_valid_token():
    auth = TokenAuth(tokens=["secret-token-123"])
    assert auth.enabled is True
    assert auth.verify("secret-token-123") is True


def test_invalid_token():
    auth = TokenAuth(tokens=["secret-token-123"])
    assert auth.verify("wrong-token") is False


def test_multiple_tokens():
    auth = TokenAuth(tokens=["token-a", "token-b"])
    assert auth.verify("token-a") is True
    assert auth.verify("token-b") is True
    assert auth.verify("token-c") is False
