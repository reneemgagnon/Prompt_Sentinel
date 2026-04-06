"""
V3_LLM_Boundary_Crypto_EndToEnd
==============================

Purpose
-------
A practical "host-enforced" boundary system for LLM-integrated chat apps.

Design Principle
---------------
The LLM is NEVER a security boundary.
The LLM can propose actions (tool calls / reads / exports), but ONLY the host runtime:
  - unseals policy (never shown to the LLM)
  - verifies signed capabilities from trusted authorities
  - enforces policy constraints (tools, params, path allowlists, quotas)
  - produces tamper-evident audit logs

This file is end-to-end and runnable as a local demo. For real deployments:
  - Replace LocalKeyStore with KMS/HSM/TPM-backed keys.
  - Persist replay cache + per-session counters (e.g., Redis).
  - Use FIPS-validated crypto modules where required.
  - Add a real policy language/engine (OPA/Rego) if rules become complex.

Dependencies
------------
pip install cryptography

Run
---
python V3_LLM_Boundary_Crypto_end_to_end.py

Demo behavior
-------------
- Shows policy sealing (AES-GCM).
- Shows signed capability issuance (Ed25519) with expiry + nonce + audience.
- Shows denials for disallowed tools / params / file paths.
- Writes an audit log with hash chaining.

Author > Renee M Gagnon
Nobot Defensive Systems Inc. Dec 2025

"""

from __future__ import annotations

import base64
import dataclasses
import fnmatch
import hashlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# =============================================================================
# CONFIG (put adjustable variables at top)
# =============================================================================

APP_VERSION = "V3.0"
DEFAULT_AUDIENCE = "local.boundary.chat.v3"
CLOCK_SKEW_SECONDS = 30

# Where the demo is allowed to read files from
DEMO_ALLOWED_DIR = Path(__file__).resolve().parent / "demo_data"
DEMO_ALLOWED_DIR.mkdir(parents=True, exist_ok=True)
(DEMO_ALLOWED_DIR / "hello.txt").write_text("Hello from an allowlisted file.\n", encoding="utf-8")

AUDIT_LOG_PATH = Path(__file__).resolve().parent / "v3_audit_log.jsonl"


# =============================================================================
# Utility: canonical JSON
# =============================================================================

def canonical_json(obj: Any) -> bytes:
    """
    Deterministic JSON encoding for signing/hashing.
    (For very high assurance, consider RFC 8785 JCS; this is a pragmatic baseline.)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# =============================================================================
# Trust authorities + permissions
# =============================================================================

class TrustAuthority(str, Enum):
    SYSTEM_ADMIN = "system_admin"
    POLICY_ENGINE = "policy_engine"
    PRIVACY_OFFICER = "privacy_officer"
    TOOL_RUNTIME = "tool_runtime"
    USER_DELEGATE = "user_delegate"


DEFAULT_AUTHORITY_PERMS: Dict[TrustAuthority, Set[str]] = {
    TrustAuthority.SYSTEM_ADMIN: {"*"},
    TrustAuthority.POLICY_ENGINE: {"update_policy", "approve_tool_call"},
    TrustAuthority.PRIVACY_OFFICER: {"approve_sensitive_export", "approve_tool_call"},
    TrustAuthority.TOOL_RUNTIME: {"sign_tool_response"},
    TrustAuthority.USER_DELEGATE: {"approve_tool_call"},  # e.g., user-granted capabilities
}


# =============================================================================
# Key management (LOCAL DEMO). Replace with KMS/HSM/TPM in production.
# =============================================================================

class LocalKeyStore:
    """
    A minimal keystore:
      - Ed25519 keypair per authority
      - AES-256 key for policy vault

    For production: do NOT store raw keys like this. Use a KMS/HSM wrapper.
    """

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._ed_priv: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._ed_pub: Dict[str, ed25519.Ed25519PublicKey] = {}
        self._aes_keys: Dict[str, bytes] = {}

    def get_or_create_ed25519(self, key_id: str) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        if key_id in self._ed_priv:
            return self._ed_priv[key_id], self._ed_pub[key_id]

        priv_path = self.root / f"{key_id}.ed25519.priv"
        pub_path = self.root / f"{key_id}.ed25519.pub"

        if priv_path.exists() and pub_path.exists():
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_path.read_bytes())
            pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_path.read_bytes())
        else:
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            priv_path.write_bytes(priv.private_bytes_raw())
            pub_path.write_bytes(pub.public_bytes_raw())

        self._ed_priv[key_id] = priv
        self._ed_pub[key_id] = pub
        return priv, pub

    def get_or_create_aes256(self, key_id: str) -> bytes:
        if key_id in self._aes_keys:
            return self._aes_keys[key_id]

        key_path = self.root / f"{key_id}.aes256.key"
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = AESGCM.generate_key(bit_length=256)
            key_path.write_bytes(key)

        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._aes_keys[key_id] = key
        return key


# =============================================================================
# Replay cache (nonce/jti) with TTL
# =============================================================================

class ReplayCache:
    """
    Simple in-memory replay cache (nonce -> exp).
    Production: store in Redis/DB with TTL.
    """

    def __init__(self, max_items: int = 100_000):
        self._exp_by_nonce: Dict[str, float] = {}
        self._max_items = max_items

    def _prune(self, now: float) -> None:
        # drop expired
        expired = [n for n, exp in self._exp_by_nonce.items() if exp <= now]
        for n in expired:
            self._exp_by_nonce.pop(n, None)

        # bound size
        if len(self._exp_by_nonce) > self._max_items:
            for nonce, _exp in sorted(self._exp_by_nonce.items(), key=lambda kv: kv[1])[: len(self._exp_by_nonce) - self._max_items]:
                self._exp_by_nonce.pop(nonce, None)

    def check_and_store(self, nonce: str, exp: float, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        self._prune(now)
        if nonce in self._exp_by_nonce:
            return False
        self._exp_by_nonce[nonce] = exp
        return True


# =============================================================================
# Capability ticket: signed instruction from authority
# =============================================================================

@dataclass(frozen=True)
class CapabilityTicket:
    """
    Cryptographically signed capability for a specific operation & scope.

    IMPORTANT:
      - The "facts" (session_id, user_id, role, tenant, etc.) should be set by the host,
        not accepted from the LLM.
      - Bind the proposed params via params_hash to prevent "sign one thing, do another".
    """
    key_id: str                # which public key verifies this
    authority: str             # TrustAuthority value (string for transport)
    aud: str                   # audience binding
    iat: int
    exp: int
    nonce: str                 # jti
    operation: str             # e.g., "approve_tool_call" or "approve_sensitive_export"
    session_id: str            # binds to a specific session
    scope: Dict[str, Any]      # e.g., {"tool":"file_read"} or {"export":"patient_data"}
    params_hash_b64: str       # sha256(canonical params) base64
    signature_b64: str         # Ed25519 signature over canonical fields (excluding signature)

    def signing_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "authority": self.authority,
            "aud": self.aud,
            "iat": self.iat,
            "exp": self.exp,
            "nonce": self.nonce,
            "operation": self.operation,
            "session_id": self.session_id,
            "scope": self.scope,
            "params_hash_b64": self.params_hash_b64,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(self.signing_dict())

    @staticmethod
    def issue(
        *,
        authority: TrustAuthority,
        operation: str,
        session_id: str,
        scope: Dict[str, Any],
        params: Dict[str, Any],
        private_key: ed25519.Ed25519PrivateKey,
        key_id: str,
        aud: str,
        ttl_seconds: int = 60,
    ) -> "CapabilityTicket":
        now = int(time.time())
        ph = sha256(canonical_json(params))
        ticket = CapabilityTicket(
            key_id=key_id,
            authority=authority.value,
            aud=aud,
            iat=now,
            exp=now + ttl_seconds,
            nonce=secrets.token_urlsafe(24),
            operation=operation,
            session_id=session_id,
            scope=scope,
            params_hash_b64=b64e(ph),
            signature_b64="",
        )
        sig = private_key.sign(ticket.signing_bytes())
        return dataclasses.replace(ticket, signature_b64=b64e(sig))


class CapabilityVerifier:
    def __init__(
        self,
        public_keys_by_id: Dict[str, ed25519.Ed25519PublicKey],
        authority_perms: Dict[TrustAuthority, Set[str]] = DEFAULT_AUTHORITY_PERMS,
        expected_audience: str = DEFAULT_AUDIENCE,
        replay_cache: Optional[ReplayCache] = None,
        clock_skew_seconds: int = CLOCK_SKEW_SECONDS,
    ):
        self.public_keys_by_id = dict(public_keys_by_id)
        self.authority_perms = authority_perms
        self.expected_audience = expected_audience
        self.replay_cache = replay_cache or ReplayCache()
        self.clock_skew_seconds = clock_skew_seconds

    def _has_permission(self, authority: TrustAuthority, operation: str) -> bool:
        perms = self.authority_perms.get(authority, set())
        return ("*" in perms) or (operation in perms)

    def verify(self, ticket: CapabilityTicket, *, expected_session_id: str, expected_params: Dict[str, Any]) -> Tuple[bool, str]:
        # Audience
        if ticket.aud != self.expected_audience:
            return False, "Wrong audience"

        # Time validity
        now = time.time()
        if now < (ticket.iat - self.clock_skew_seconds):
            return False, "Ticket not valid yet"
        if now > (ticket.exp + self.clock_skew_seconds):
            return False, "Ticket expired"

        # Replay defense
        if not self.replay_cache.check_and_store(ticket.nonce, float(ticket.exp), now=now):
            return False, "Replay detected"

        # Session binding
        if ticket.session_id != expected_session_id:
            return False, "Wrong session_id"

        # Permission binding
        try:
            auth = TrustAuthority(ticket.authority)
        except Exception:
            return False, "Unknown authority"

        if not self._has_permission(auth, ticket.operation):
            return False, "Authority not permitted for operation"

        # Params binding
        expected_ph = sha256(canonical_json(expected_params))
        if b64e(expected_ph) != ticket.params_hash_b64:
            return False, "params_hash mismatch"

        # Signature
        pub = self.public_keys_by_id.get(ticket.key_id)
        if pub is None:
            return False, "Unknown key_id"
        try:
            pub.verify(b64d(ticket.signature_b64), ticket.signing_bytes())
            return True, "OK"
        except (InvalidSignature, ValueError):
            return False, "Invalid signature"


# =============================================================================
# Policy vault: seal/unseal policy (policy never goes into model context)
# =============================================================================

@dataclass(frozen=True)
class SealedPolicyBundle:
    """
    Transport format for sealed policy.
    """
    key_id: str
    version: str
    created_at: int
    nonce_b64: str
    aad_b64: str
    ciphertext_b64: str


class PolicyVaultV3:
    """
    AES-GCM policy vault, with AAD binding to policy hash + metadata.
    """

    def __init__(self, *, key_id: str, get_key: Callable[[], bytes]):
        self.key_id = key_id
        self._get_key = get_key

    def _key(self) -> bytes:
        k = self._get_key()
        if not isinstance(k, (bytes, bytearray)) or len(k) != 32:
            raise ValueError("Policy AES key must be 32 bytes")
        return bytes(k)

    @staticmethod
    def policy_hash(policy_json: Dict[str, Any]) -> bytes:
        return sha256(canonical_json(policy_json))

    def seal(self, policy_json: Dict[str, Any], *, version: str = "1") -> Tuple[SealedPolicyBundle, str]:
        """
        Returns (sealed_bundle, policy_hash_hex)
        """
        created_at = int(time.time())
        nonce = secrets.token_bytes(12)
        ph = self.policy_hash(policy_json)

        aad = canonical_json({
            "key_id": self.key_id,
            "version": version,
            "created_at": created_at,
            "policy_hash_b64": b64e(ph),
        })

        aesgcm = AESGCM(self._key())
        ct = aesgcm.encrypt(nonce, canonical_json(policy_json), aad)

        bundle = SealedPolicyBundle(
            key_id=self.key_id,
            version=version,
            created_at=created_at,
            nonce_b64=b64e(nonce),
            aad_b64=b64e(aad),
            ciphertext_b64=b64e(ct),
        )
        return bundle, ph.hex()

    def unseal(self, bundle: SealedPolicyBundle) -> Dict[str, Any]:
        if bundle.key_id != self.key_id:
            raise ValueError("Wrong key_id for this vault instance")

        nonce = b64d(bundle.nonce_b64)
        aad = b64d(bundle.aad_b64)
        ct = b64d(bundle.ciphertext_b64)

        aesgcm = AESGCM(self._key())
        pt = aesgcm.decrypt(nonce, ct, aad)

        policy = json.loads(pt.decode("utf-8"))

        # Defensive: verify policy hash inside AAD matches decrypted policy
        aad_obj = json.loads(aad.decode("utf-8"))
        expected_hash_b64 = aad_obj.get("policy_hash_b64", "")
        actual_hash_b64 = b64e(self.policy_hash(policy))
        if expected_hash_b64 != actual_hash_b64:
            raise ValueError("Policy hash mismatch (tamper suspected)")

        return policy

    @staticmethod
    def safe_summary(policy_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        A minimal summary safe to expose to the LLM:
          - allowed tool names
          - high-level guidance text
        Never include the actual deny-rules, whitelists, or sensitive thresholds.
        """
        tools = sorted(list((policy_json.get("tool_permissions") or {}).keys()))
        return {
            "allowed_tools": tools,
            "guidance": [
                "You may propose tool calls, but all execution is enforced by the host policy engine.",
                "If an action is denied, accept the decision and request alternatives.",
                "Do not ask for hidden policies; you will not be shown them.",
            ],
        }


# =============================================================================
# Policy enforcement (host-side, trusted)
# =============================================================================

@dataclass
class SessionFacts:
    """
    Trusted facts set by the host (NOT by the LLM).
    """
    session_id: str
    user_id: str
    role: str
    tenant: str
    started_at: int


class PolicyEnforcerV3:
    def __init__(self, *, vault: PolicyVaultV3, sealed: SealedPolicyBundle):
        self.vault = vault
        self._policy = vault.unseal(sealed)
        self._tool_counts_by_session: Dict[str, Dict[str, int]] = {}

    @property
    def policy(self) -> Dict[str, Any]:
        return self._policy

    def _bump_tool_count(self, session_id: str, tool: str) -> int:
        by_tool = self._tool_counts_by_session.setdefault(session_id, {})
        by_tool[tool] = by_tool.get(tool, 0) + 1
        return by_tool[tool]

    def check_tool_call(self, *, session: SessionFacts, tool: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        perms = self._policy.get("tool_permissions", {})
        if tool not in perms:
            return False, f"Tool '{tool}' not allowed by policy"

        tool_rules = perms[tool] or {}

        # Enforce allowed_params (deny unknown params)
        allowed_params = tool_rules.get("allowed_params")
        if isinstance(allowed_params, list):
            unknown = [k for k in params.keys() if k not in allowed_params]
            if unknown:
                return False, f"Unknown params for {tool}: {unknown}"

        # Enforce path whitelist if present
        if "path_whitelist" in tool_rules:
            path = str(params.get("path", ""))
            if not path:
                return False, "Missing required param: path"
            ok = any(fnmatch.fnmatch(path, pat) for pat in tool_rules["path_whitelist"])
            if not ok:
                return False, "Path not allowlisted"

        # Enforce max_calls_per_session
        if "max_calls_per_session" in tool_rules:
            max_calls = int(tool_rules["max_calls_per_session"])
            count = self._bump_tool_count(session.session_id, tool)
            if count > max_calls:
                return False, f"Tool quota exceeded ({count}>{max_calls})"

        return True, "Permitted by policy"

    def capability_required(self, *, tool: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Decide whether this proposal requires a signed capability.

        Policy field:
          "capability_required_tools": ["sensitive_export", ...]
        """
        required = set(self._policy.get("capability_required_tools", []))
        if tool in required:
            return True, "Capability required by tool classification"

        # Optional: trigger capability if params indicate sensitivity
        if tool == "file_read":
            path = str(params.get("path", ""))
            if "patient" in path.lower() or "phi" in path.lower():
                return True, "Capability required due to sensitive path heuristic"

        return False, "No capability required"


# =============================================================================
# Tool registry (trusted execution)
# =============================================================================

class ToolError(Exception):
    pass


class ToolRegistry:
    def __init__(self, *, base_dir: Path):
        self.base_dir = base_dir
        self._tools: Dict[str, Callable[[Dict[str, Any]], Any]] = {
            "file_read": self._file_read,
            "calc_sha256": self._calc_sha256,
            "echo": self._echo,
            "sensitive_export": self._sensitive_export_stub,
        }

    def list_tools(self) -> List[str]:
        return sorted(self._tools.keys())

    def call(self, tool: str, params: Dict[str, Any]) -> Any:
        fn = self._tools.get(tool)
        if not fn:
            raise ToolError(f"Unknown tool: {tool}")
        return fn(params)

    def _file_read(self, params: Dict[str, Any]) -> str:
        path = params.get("path")
        if not isinstance(path, str) or not path:
            raise ToolError("file_read requires 'path'")

        # Safety: constrain to base_dir as an additional guardrail (even if policy fails)
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = (self.base_dir / p).resolve()
        else:
            p = p.resolve()

        if self.base_dir.resolve() not in p.parents and p != self.base_dir.resolve():
            raise ToolError("file_read blocked by base_dir constraint")

        if not p.exists() or not p.is_file():
            raise ToolError("file_read target missing or not a file")

        # Cap read size
        data = p.read_bytes()
        if len(data) > 64_000:
            raise ToolError("file_read: file too large for demo")
        return data.decode("utf-8", errors="replace")

    def _calc_sha256(self, params: Dict[str, Any]) -> Dict[str, str]:
        s = params.get("text", "")
        if not isinstance(s, str):
            raise ToolError("calc_sha256 requires 'text' as string")
        return {"sha256_hex": sha256(s.encode("utf-8")).hex()}

    def _echo(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"echo": params}

    def _sensitive_export_stub(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stub for a privileged operation.
        In production this might export PHI, write to secure store, etc.
        """
        return {"status": "export_complete", "details": "stubbed_export"}


# =============================================================================
# Tamper-evident audit log (hash-chained JSONL)
# =============================================================================

class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        try:
            last = None
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)
            if last and "entry_hash" in last:
                return str(last["entry_hash"])
        except Exception:
            pass
        return "0" * 64

    def append(self, entry: Dict[str, Any]) -> None:
        entry = dict(entry)
        entry["ts"] = int(time.time())
        entry["prev_hash"] = self._last_hash
        entry_bytes = canonical_json({k: entry[k] for k in sorted(entry.keys()) if k != "entry_hash"})
        entry_hash = sha256(entry_bytes).hex()
        entry["entry_hash"] = entry_hash
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._last_hash = entry_hash


# =============================================================================
# Boundary App V3 (end-to-end)
# =============================================================================

class BoundaryAppV3:
    """
    Core "hardened chat runtime":
      - accepts an untrusted LLM action proposal
      - validates vs sealed policy
      - optionally requires a signed capability
      - executes tool in trusted registry
      - records audit
    """

    def __init__(
        self,
        *,
        enforcer: PolicyEnforcerV3,
        tools: ToolRegistry,
        cap_verifier: CapabilityVerifier,
        audit: AuditLog,
    ):
        self.enforcer = enforcer
        self.tools = tools
        self.cap_verifier = cap_verifier
        self.audit = audit

    def safe_policy_summary_for_llm(self) -> Dict[str, Any]:
        return PolicyVaultV3.safe_summary(self.enforcer.policy)

    def handle_action_proposal(
        self,
        *,
        session: SessionFacts,
        proposal: Dict[str, Any],
        capability: Optional[CapabilityTicket] = None,
    ) -> Dict[str, Any]:
        """
        proposal is expected to be an LLM output like:
          {"tool":"file_read","params":{"path":"demo_data/hello.txt"}}

        Returns a structured decision/result safe to feed back to the LLM.
        """
        tool = proposal.get("tool")
        params = proposal.get("params", {})

        if not isinstance(tool, str) or not tool:
            return {"allowed": False, "reason": "Invalid proposal: missing tool"}
        if not isinstance(params, dict):
            return {"allowed": False, "reason": "Invalid proposal: params must be dict"}

        allowed, reason = self.enforcer.check_tool_call(session=session, tool=tool, params=params)
        cap_needed, cap_reason = self.enforcer.capability_required(tool=tool, params=params)

        decision = {
            "allowed": False,
            "reason": reason,
            "capability_required": cap_needed,
            "capability_reason": cap_reason,
            "tool": tool,
        }

        if not allowed:
            self.audit.append({
                "event": "tool_call_denied",
                "session_id": session.session_id,
                "user_id": session.user_id,
                "tool": tool,
                "reason": reason,
            })
            return decision

        if cap_needed:
            if capability is None:
                decision["reason"] = "Denied: capability required but not provided"
                self.audit.append({
                    "event": "tool_call_denied",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": tool,
                    "reason": decision["reason"],
                })
                return decision

            ok, cap_msg = self.cap_verifier.verify(capability, expected_session_id=session.session_id, expected_params=params)
            if not ok:
                decision["reason"] = f"Denied: invalid capability ({cap_msg})"
                self.audit.append({
                    "event": "tool_call_denied",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": tool,
                    "reason": decision["reason"],
                })
                return decision

        # Execute tool
        try:
            result = self.tools.call(tool, params)
            decision["allowed"] = True
            decision["reason"] = "Allowed"
            decision["result"] = result
            self.audit.append({
                "event": "tool_call_allowed",
                "session_id": session.session_id,
                "user_id": session.user_id,
                "tool": tool,
                "params_hash": sha256(canonical_json(params)).hex(),
            })
            return decision
        except Exception as e:
            decision["allowed"] = False
            decision["reason"] = f"Tool execution error: {type(e).__name__}: {e}"
            self.audit.append({
                "event": "tool_call_error",
                "session_id": session.session_id,
                "user_id": session.user_id,
                "tool": tool,
                "error": decision["reason"],
            })
            return decision


# =============================================================================
# Demo policy (you would store/edit this outside the LLM)
# =============================================================================

def build_demo_policy() -> Dict[str, Any]:
    """
    This policy is intentionally simple and JSON-based for demo.
    In production, consider a real policy engine (e.g., OPA/Rego).
    """
    allow_glob = str(DEMO_ALLOWED_DIR / "*")
    return {
        "tool_permissions": {
            "file_read": {
                "allowed_params": ["path"],
                "path_whitelist": [allow_glob, "demo_data/*"],  # allow relative and absolute under demo_data
                "max_calls_per_session": 5,
            },
            "calc_sha256": {
                "allowed_params": ["text"],
                "max_calls_per_session": 50,
            },
            "echo": {
                "allowed_params": ["message", "any"],
                "max_calls_per_session": 20,
            },
            "sensitive_export": {
                "allowed_params": ["dataset", "format"],
                "max_calls_per_session": 2,
            },
        },
        "capability_required_tools": ["sensitive_export"],
        "meta": {
            "policy_name": "demo_policy",
            "notes": "file_read restricted to demo_data only",
        }
    }


# =============================================================================
# Minimal "LLM output" handling for demo
# =============================================================================

def parse_proposal(s: str) -> Dict[str, Any]:
    """
    Expect JSON tool proposal. This simulates LLM structured output.
    """
    obj = json.loads(s)
    if not isinstance(obj, dict):
        raise ValueError("Proposal must be a JSON object")
    return obj


# =============================================================================
# MAIN: end-to-end demo
# =============================================================================

def main() -> None:
    print(f"Boundary Crypto Chat (V3) - {APP_VERSION}")
    print(f"Allowed demo directory: {DEMO_ALLOWED_DIR}")
    print(f"Audit log: {AUDIT_LOG_PATH}")
    print()

    # Local keystore (demo)
    ks = LocalKeyStore(root=Path(__file__).resolve().parent / ".v3_keys")

    # Keys
    # - AES key for policy vault
    policy_key_id = "policy_vault_key_v3"
    policy_aes = ks.get_or_create_aes256(policy_key_id)

    # - Ed25519 keys for authorities
    pub_by_id: Dict[str, ed25519.Ed25519PublicKey] = {}
    priv_by_id: Dict[str, ed25519.Ed25519PrivateKey] = {}
    for auth in TrustAuthority:
        key_id = f"{auth.value}.v3"
        priv, pub = ks.get_or_create_ed25519(key_id)
        priv_by_id[key_id] = priv
        pub_by_id[key_id] = pub

    # Policy vault + sealing
    vault = PolicyVaultV3(key_id=policy_key_id, get_key=lambda: policy_aes)
    policy = build_demo_policy()
    sealed, policy_hash_hex = vault.seal(policy, version="demo-1")
    print(f"Sealed policy hash: {policy_hash_hex}")
    print(f"Policy summary for LLM: {json.dumps(vault.safe_summary(policy), indent=2)}")
    print()

    # Enforcer + tools + verifier + audit
    enforcer = PolicyEnforcerV3(vault=vault, sealed=sealed)
    tools = ToolRegistry(base_dir=DEMO_ALLOWED_DIR)
    verifier = CapabilityVerifier(public_keys_by_id=pub_by_id, expected_audience=DEFAULT_AUDIENCE)
    audit = AuditLog(AUDIT_LOG_PATH)

    app = BoundaryAppV3(enforcer=enforcer, tools=tools, cap_verifier=verifier, audit=audit)

    # Session facts (trusted)
    session = SessionFacts(
        session_id=secrets.token_urlsafe(12),
        user_id="local_user",
        role="operator",
        tenant="local",
        started_at=int(time.time()),
    )

    print("Demo session started.")
    print(f"session_id = {session.session_id}")
    print()
    print("Enter a JSON proposal (simulating LLM structured output), examples:")
    print('  {"tool":"file_read","params":{"path":"demo_data/hello.txt"}}')
    print('  {"tool":"file_read","params":{"path":"/etc/passwd"}}')
    print('  {"tool":"sensitive_export","params":{"dataset":"patient_data","format":"json"}}')
    print()
    print("For sensitive_export, you can request a capability by typing:")
    print("  /cap privacy_officer")
    print("  /cap system_admin")
    print("Then re-run the sensitive_export proposal.")
    print("Type /quit to exit.")
    print()

    last_cap: Optional[CapabilityTicket] = None

    while True:
        try:
            line = input("proposal> ").strip()
        except EOFError:
            print()
            break

        if not line:
            continue
        if line == "/quit":
            break

        if line.startswith("/cap"):
            parts = line.split()
            if len(parts) != 2:
                print("Usage: /cap <authority>, e.g. /cap privacy_officer")
                continue
            auth_name = parts[1]
            try:
                auth = TrustAuthority(auth_name)
            except Exception:
                print(f"Unknown authority: {auth_name}")
                continue

            # For demo: issue a capability for approve_tool_call scoped to sensitive_export
            cap_key_id = f"{auth.value}.v3"
            priv = priv_by_id[cap_key_id]
            scope = {"tool": "sensitive_export"}
            # Params hash will be checked against the NEXT proposal you run.
            # We'll issue with empty params now, and regenerate on demand when you run a proposal.
            last_cap = CapabilityTicket.issue(
                authority=auth,
                operation="approve_tool_call",
                session_id=session.session_id,
                scope=scope,
                params={},  # placeholder; will be replaced after you enter the real proposal
                private_key=priv,
                key_id=cap_key_id,
                aud=DEFAULT_AUDIENCE,
                ttl_seconds=120,
            )
            print(f"Issued capability from {auth.value} (NOTE: will be re-issued with params on next run).")
            continue

        try:
            proposal = parse_proposal(line)
        except Exception as e:
            print(f"Invalid proposal: {e}")
            continue

        tool = proposal.get("tool")
        params = proposal.get("params", {})

        # If we have a last_cap, re-issue it binding to current params (demo convenience)
        cap_to_use = None
        if last_cap is not None and isinstance(tool, str):
            try:
                auth = TrustAuthority(last_cap.authority)
                cap_key_id = last_cap.key_id
                priv = priv_by_id[cap_key_id]
                cap_to_use = CapabilityTicket.issue(
                    authority=auth,
                    operation=last_cap.operation,
                    session_id=session.session_id,
                    scope=last_cap.scope,
                    params=params if isinstance(params, dict) else {},
                    private_key=priv,
                    key_id=cap_key_id,
                    aud=DEFAULT_AUDIENCE,
                    ttl_seconds=120,
                )
            except Exception:
                cap_to_use = last_cap

        decision = app.handle_action_proposal(session=session, proposal=proposal, capability=cap_to_use)
        print(json.dumps(decision, indent=2, ensure_ascii=False))

    print("\nGoodbye.")
    print(f"Audit log written to: {AUDIT_LOG_PATH}")


if __name__ == "__main__":
    main()
