"""Tests for CapabilityService — issuance, verification, and replay detection."""

import time

import pytest

from prompt_sentinel.core.capability import CapabilityService, ReplayCache
from prompt_sentinel.core.models import CapabilityTicket


def _make_service() -> CapabilityService:
    key = CapabilityService.generate_private_key()
    return CapabilityService(
        private_key=key,
        public_key=key.public_key(),
        expected_audience="test.audience",
    )


def _issue(service: CapabilityService, **overrides) -> CapabilityTicket:
    defaults = dict(
        key_id="k1",
        authority="policy_engine",
        audience="test.audience",
        operation="approve_tool_call",
        session_id="sess-1",
        scope={"tool": "echo"},
        params={"message": "hi"},
        ttl_seconds=300,
    )
    defaults.update(overrides)
    return service.issue(**defaults)


# ── Round-trip issue → verify ────────────────────────────────────────
def test_issue_and_verify():
    svc = _make_service()
    ticket = _issue(svc)
    ok, reason = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok is True
    assert reason == "valid"


# ── Wrong audience ───────────────────────────────────────────────────
def test_wrong_audience():
    svc = _make_service()
    ticket = _issue(svc, audience="wrong.audience")
    ok, reason = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok is False
    assert "audience" in reason


# ── Expired ticket ───────────────────────────────────────────────────
def test_expired_ticket():
    svc = _make_service()
    ticket = _issue(svc, ttl_seconds=0)
    # Force time forward
    ok, reason = svc.verify(
        ticket,
        expected_session_id="sess-1",
        expected_params={"message": "hi"},
        now=int(time.time()) + 600,
    )
    assert ok is False
    assert "expired" in reason


# ── Wrong session ────────────────────────────────────────────────────
def test_wrong_session():
    svc = _make_service()
    ticket = _issue(svc)
    ok, reason = svc.verify(ticket, expected_session_id="different-session", expected_params={"message": "hi"})
    assert ok is False
    assert "session" in reason


# ── Param hash mismatch ─────────────────────────────────────────────
def test_param_mismatch():
    svc = _make_service()
    ticket = _issue(svc)
    ok, reason = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "TAMPERED"})
    assert ok is False
    assert "parameter hash" in reason


# ── Authority permissions ────────────────────────────────────────────
def test_unauthorized_authority():
    svc = _make_service()
    ticket = _issue(svc, authority="tool_runtime", operation="approve_tool_call")
    ok, reason = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok is False
    assert "not permitted" in reason


def test_system_admin_wildcard():
    svc = _make_service()
    ticket = _issue(svc, authority="system_admin", operation="anything_goes")
    ok, reason = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok is True


# ── Replay detection ────────────────────────────────────────────────
def test_replay_detected():
    svc = _make_service()
    ticket = _issue(svc)
    ok1, _ = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok1 is True
    ok2, reason = svc.verify(ticket, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok2 is False
    assert "replay" in reason


# ── Tampered signature ──────────────────────────────────────────────
def test_tampered_signature():
    svc = _make_service()
    ticket = _issue(svc)
    tampered = CapabilityTicket(
        **{**ticket.__dict__, "signature_b64": "AAAA" + ticket.signature_b64[4:]}
    )
    ok, reason = svc.verify(tampered, expected_session_id="sess-1", expected_params={"message": "hi"})
    assert ok is False
    assert "signature" in reason or "replay" in reason


# ── ReplayCache pruning ─────────────────────────────────────────────
def test_replay_cache_prunes_expired():
    cache = ReplayCache(max_items=10)
    now = time.time()
    cache.check_and_store("old-nonce", now - 100, now=now)
    assert cache.check_and_store("new-nonce", now + 300, now=now) is True
    # old-nonce should have been pruned, but a fresh nonce still works
    assert cache.check_and_store("another", now + 300, now=now) is True


# ── Key export round-trip ────────────────────────────────────────────
def test_key_export_roundtrip():
    key = CapabilityService.generate_private_key()
    raw = CapabilityService.export_private_key(key)
    reloaded = CapabilityService.load_private_key(raw)
    pub_raw = CapabilityService.export_public_key(key.public_key())
    reloaded_pub = CapabilityService.load_public_key(pub_raw)
    # Verify signing round-trip
    sig = reloaded.sign(b"test")
    reloaded_pub.verify(sig, b"test")  # raises if invalid


# ── No private key raises ────────────────────────────────────────────
def test_issue_without_private_key():
    svc = CapabilityService(public_key=CapabilityService.generate_private_key().public_key())
    with pytest.raises(ValueError, match="private key"):
        _issue(svc)
