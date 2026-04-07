"""Tests for PolicyVault — AES-256-GCM seal/unseal."""

import secrets

import pytest

from prompt_sentinel.core.models import SealedPolicyBundle
from prompt_sentinel.core.policy_vault import PolicyVault


POLICY = {
    "tool_permissions": {
        "echo": {"allowed_params": ["message"], "max_calls_per_session": 5}
    },
    "capability_required_tools": [],
}


def _vault() -> PolicyVault:
    return PolicyVault(key_id="test-key", key=secrets.token_bytes(32))


def test_seal_unseal_roundtrip():
    vault = _vault()
    bundle, policy_hash = vault.seal(POLICY, version="1")
    assert isinstance(bundle, SealedPolicyBundle)
    assert len(policy_hash) == 64  # hex sha256
    recovered = vault.unseal(bundle)
    assert recovered == POLICY


def test_wrong_key_fails():
    v1 = _vault()
    v2 = PolicyVault(key_id="test-key", key=secrets.token_bytes(32))
    bundle, _ = v1.seal(POLICY)
    with pytest.raises(Exception):
        v2.unseal(bundle)


def test_wrong_key_id_fails():
    vault = _vault()
    bundle, _ = vault.seal(POLICY)
    other = PolicyVault(key_id="other-key", key=vault.key)
    with pytest.raises(ValueError, match="key_id"):
        other.unseal(bundle)


def test_safe_summary_hides_internals():
    summary = PolicyVault.safe_summary(POLICY)
    assert "echo" in summary["allowed_tools"]
    assert "guidance" in summary
    # Should not leak policy internals
    assert "tool_permissions" not in str(summary["guidance"])


def test_invalid_key_length():
    with pytest.raises(ValueError, match="32 bytes"):
        PolicyVault(key_id="bad", key=b"short")
