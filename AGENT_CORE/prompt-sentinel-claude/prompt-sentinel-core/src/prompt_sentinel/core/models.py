"""Data models for the core runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ToolProposal:
    tool: str
    params: Dict[str, Any]


@dataclass(frozen=True)
class SessionFacts:
    session_id: str
    user_id: str
    role: str = "developer"
    tenant: str = "default"


@dataclass(frozen=True)
class CapabilityTicket:
    key_id: str
    authority: str
    audience: str
    issued_at: int
    expires_at: int
    nonce: str
    operation: str
    session_id: str
    scope: Dict[str, Any]
    params_hash_b64: str
    signature_b64: str


@dataclass(frozen=True)
class SealedPolicyBundle:
    key_id: str
    version: str
    created_at: int
    nonce_b64: str
    aad_b64: str
    ciphertext_b64: str


@dataclass
class EnforcementDecision:
    allowed: bool
    reason: str
    tool: str
    capability_required: bool = False
    capability_reason: str = ""
    result: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
