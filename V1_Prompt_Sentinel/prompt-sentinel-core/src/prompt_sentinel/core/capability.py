"""Capability issuance and verification."""

from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .models import CapabilityTicket
from .utils import b64d, b64e, canonical_json, sha256_bytes


DEFAULT_AUDIENCE = "local.prompt-sentinel"
CLOCK_SKEW_SECONDS = 30
DEFAULT_AUTHORITY_PERMS: Dict[str, Set[str]] = {
    "system_admin": {"*"},
    "policy_engine": {"update_policy", "approve_tool_call"},
    "privacy_officer": {"approve_sensitive_export", "approve_tool_call"},
    "tool_runtime": {"sign_tool_response"},
    "user_delegate": {"approve_tool_call"},
}


def _ticket_payload(ticket: CapabilityTicket) -> Dict[str, Any]:
    return {
        "key_id": ticket.key_id,
        "authority": ticket.authority,
        "audience": ticket.audience,
        "issued_at": ticket.issued_at,
        "expires_at": ticket.expires_at,
        "nonce": ticket.nonce,
        "operation": ticket.operation,
        "session_id": ticket.session_id,
        "scope": ticket.scope,
        "params_hash_b64": ticket.params_hash_b64,
    }


class ReplayCache:
    """Simple in-memory replay cache with expiration pruning."""

    def __init__(self, max_items: int = 100_000):
        self._exp_by_nonce: Dict[str, float] = {}
        self._max_items = max_items

    def _prune(self, now: float) -> None:
        expired = [nonce for nonce, exp in self._exp_by_nonce.items() if exp <= now]
        for nonce in expired:
            self._exp_by_nonce.pop(nonce, None)
        if len(self._exp_by_nonce) > self._max_items:
            overflow = len(self._exp_by_nonce) - self._max_items
            for nonce, _exp in sorted(self._exp_by_nonce.items(), key=lambda item: item[1])[:overflow]:
                self._exp_by_nonce.pop(nonce, None)

    def check_and_store(self, nonce: str, exp: float, *, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        self._prune(now)
        if nonce in self._exp_by_nonce:
            return False
        self._exp_by_nonce[nonce] = exp
        return True


class CapabilityService:
    """Issue and verify signed approval tickets."""

    def __init__(
        self,
        *,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        public_key: Optional[ed25519.Ed25519PublicKey] = None,
        expected_audience: str = DEFAULT_AUDIENCE,
        authority_perms: Optional[Dict[str, Set[str]]] = None,
        replay_cache: Optional[ReplayCache] = None,
        clock_skew_seconds: int = CLOCK_SKEW_SECONDS,
    ):
        self.private_key = private_key
        self.public_key = public_key or (private_key.public_key() if private_key else None)
        self.expected_audience = expected_audience
        self.authority_perms = authority_perms or DEFAULT_AUTHORITY_PERMS
        self.replay_cache = replay_cache or ReplayCache()
        self.clock_skew_seconds = clock_skew_seconds

    @staticmethod
    def generate_private_key() -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()

    @staticmethod
    def load_private_key(raw: bytes) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def load_public_key(raw: bytes) -> ed25519.Ed25519PublicKey:
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def export_private_key(key: ed25519.Ed25519PrivateKey) -> bytes:
        return key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def export_public_key(key: ed25519.Ed25519PublicKey) -> bytes:
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def params_hash(params: Dict[str, Any]) -> str:
        return b64e(sha256_bytes(canonical_json(params)))

    def issue(
        self,
        *,
        key_id: str,
        authority: str,
        audience: str,
        operation: str,
        session_id: str,
        scope: Dict[str, Any],
        params: Dict[str, Any],
        ttl_seconds: int = 300,
    ) -> CapabilityTicket:
        if self.private_key is None:
            raise ValueError("CapabilityService requires a private key to issue tickets")
        issued_at = int(time.time())
        unsigned = CapabilityTicket(
            key_id=key_id,
            authority=authority,
            audience=audience,
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            nonce=secrets.token_urlsafe(24),
            operation=operation,
            session_id=session_id,
            scope=scope,
            params_hash_b64=self.params_hash(params),
            signature_b64="",
        )
        signature = self.private_key.sign(canonical_json(_ticket_payload(unsigned)))
        return CapabilityTicket(**{**unsigned.__dict__, "signature_b64": b64e(signature)})

    def _has_permission(self, authority: str, operation: str) -> bool:
        perms = self.authority_perms.get(authority, set())
        return "*" in perms or operation in perms

    def verify(
        self,
        ticket: CapabilityTicket,
        *,
        expected_session_id: str,
        expected_params: Dict[str, Any],
        now: Optional[int] = None,
    ) -> Tuple[bool, str]:
        if self.public_key is None:
            raise ValueError("CapabilityService requires a public key to verify tickets")
        now_float = time.time() if now is None else float(now)
        if ticket.audience != self.expected_audience:
            return False, "wrong audience"
        if now_float < float(ticket.issued_at - self.clock_skew_seconds):
            return False, "ticket not valid yet"
        if now_float > float(ticket.expires_at + self.clock_skew_seconds):
            return False, "expired"
        if not self.replay_cache.check_and_store(ticket.nonce, float(ticket.expires_at), now=now_float):
            return False, "replay detected"
        if ticket.session_id != expected_session_id:
            return False, "wrong session"
        if not self._has_permission(ticket.authority, ticket.operation):
            return False, "authority not permitted"
        if ticket.params_hash_b64 != self.params_hash(expected_params):
            return False, "parameter hash mismatch"
        try:
            self.public_key.verify(
                b64d(ticket.signature_b64),
                canonical_json(_ticket_payload(ticket)),
            )
        except InvalidSignature:
            return False, "invalid signature"
        return True, "valid"
