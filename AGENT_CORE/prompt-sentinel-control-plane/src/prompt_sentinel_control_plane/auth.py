"""Bearer-token authentication for the control plane.

Supports two modes:
  1. Static token list  – set via PROMPT_SENTINEL_API_TOKENS env var
     (comma-separated) or passed at construction time.
  2. Disabled           – when no tokens are configured (dev mode).

Production deployments should replace this with OIDC / JWT validation
backed by your identity provider.
"""

from __future__ import annotations

import hmac
import os
from typing import Optional, Sequence

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer_scheme = HTTPBearer(auto_error=False)


class TokenAuth:
    """Validates bearer tokens against a static allow list."""

    def __init__(self, tokens: Optional[Sequence[str]] = None):
        env_tokens = os.environ.get("PROMPT_SENTINEL_API_TOKENS", "")
        supplied = list(tokens or [])
        from_env = [t.strip() for t in env_tokens.split(",") if t.strip()]
        self.tokens = supplied or from_env
        self.enabled = len(self.tokens) > 0

    def verify(self, token: str) -> bool:
        if not self.enabled:
            return True
        return any(hmac.compare_digest(token, t) for t in self.tokens)


_default_auth = TokenAuth()


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> str:
    """FastAPI dependency that enforces bearer token auth when enabled."""
    if not _default_auth.enabled:
        return "anonymous"
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    if not _default_auth.verify(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bearer token",
        )
    return credentials.credentials
