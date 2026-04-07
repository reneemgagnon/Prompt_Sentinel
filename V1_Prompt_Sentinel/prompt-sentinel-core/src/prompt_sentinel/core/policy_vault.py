"""Policy sealing helpers."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import SealedPolicyBundle
from .utils import b64d, b64e, canonical_json, sha256_bytes


class PolicyVault:
    """Seal and unseal policies outside model context."""

    def __init__(self, *, key_id: str, key: bytes):
        if len(key) != 32:
            raise ValueError("Policy key must be 32 bytes for AES-256-GCM")
        self.key_id = key_id
        self.key = key

    def seal(self, policy_json: Dict[str, Any], *, version: str = "1") -> Tuple[SealedPolicyBundle, str]:
        created_at = int(time.time())
        nonce = secrets.token_bytes(12)
        policy_hash = sha256_bytes(canonical_json(policy_json))
        aad = canonical_json(
            {
                "key_id": self.key_id,
                "version": version,
                "created_at": created_at,
                "policy_hash_b64": b64e(policy_hash),
            }
        )
        ciphertext = AESGCM(self.key).encrypt(nonce, canonical_json(policy_json), aad)
        bundle = SealedPolicyBundle(
            key_id=self.key_id,
            version=version,
            created_at=created_at,
            nonce_b64=b64e(nonce),
            aad_b64=b64e(aad),
            ciphertext_b64=b64e(ciphertext),
        )
        return bundle, policy_hash.hex()

    def unseal(self, bundle: SealedPolicyBundle) -> Dict[str, Any]:
        if bundle.key_id != self.key_id:
            raise ValueError("Policy bundle key_id does not match vault key")
        nonce = b64d(bundle.nonce_b64)
        aad = b64d(bundle.aad_b64)
        ciphertext = b64d(bundle.ciphertext_b64)
        plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, aad)
        policy = json.loads(plaintext.decode("utf-8"))
        expected_hash = json.loads(aad.decode("utf-8"))["policy_hash_b64"]
        actual_hash = b64e(sha256_bytes(canonical_json(policy)))
        if expected_hash != actual_hash:
            raise ValueError("Policy hash mismatch")
        return policy

    @staticmethod
    def safe_summary(policy_json: Dict[str, Any]) -> Dict[str, Any]:
        tool_permissions = policy_json.get("tool_permissions") or {}
        return {
            "allowed_tools": sorted(tool_permissions.keys()),
            "guidance": [
                "Tool execution is enforced by the host runtime.",
                "If an action is denied, explain the denial and request a safer alternative.",
                "Never ask for hidden policy internals.",
            ],
        }
