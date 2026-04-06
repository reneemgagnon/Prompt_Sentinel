"""Shared runtime helpers that wrap the core primitives."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .audit import AuditChain
from .boundary_app import BoundaryApp
from .capability import CapabilityService, DEFAULT_AUDIENCE
from .enforcer import PolicyEnforcer
from .models import CapabilityTicket, SessionFacts, ToolProposal
from .tool_registry import ToolRegistry


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def resolve_default_policy_path() -> Path:
    return Path(__file__).resolve().parents[1] / "policies" / "default-policy.json"


def ensure_keypair(private_key_path: Path, public_key_path: Optional[Path] = None) -> Tuple[Path, Path]:
    private_key_path = Path(private_key_path)
    public_key_path = Path(public_key_path) if public_key_path else private_key_path.with_suffix(private_key_path.suffix + ".pub")
    if private_key_path.exists() and public_key_path.exists():
        return private_key_path, public_key_path
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    key = CapabilityService.generate_private_key()
    private_key_path.write_bytes(CapabilityService.export_private_key(key))
    public_key_path.write_bytes(CapabilityService.export_public_key(key.public_key()))
    return private_key_path, public_key_path


def load_capability_service(
    *,
    private_key_path: Optional[Path] = None,
    public_key_path: Optional[Path] = None,
    expected_audience: str = DEFAULT_AUDIENCE,
) -> CapabilityService:
    private_key = None
    public_key = None
    if private_key_path:
        private_key = CapabilityService.load_private_key(Path(private_key_path).read_bytes())
    if public_key_path:
        public_key = CapabilityService.load_public_key(Path(public_key_path).read_bytes())
    elif private_key is not None:
        public_key = private_key.public_key()
    return CapabilityService(
        private_key=private_key,
        public_key=public_key,
        expected_audience=expected_audience,
    )


def build_boundary_app(
    *,
    policy_path: Optional[Path],
    audit_log_path: Path,
    base_dir: Path,
    public_key_path: Optional[Path] = None,
    expected_audience: str = DEFAULT_AUDIENCE,
) -> BoundaryApp:
    policy = load_json(policy_path or resolve_default_policy_path())
    enforcer = PolicyEnforcer(policy)
    tools = ToolRegistry(base_dir=base_dir)
    audit = AuditChain(audit_log_path)
    capability_service = None
    if public_key_path and Path(public_key_path).exists():
        capability_service = load_capability_service(public_key_path=public_key_path, expected_audience=expected_audience)
    return BoundaryApp(
        enforcer=enforcer,
        tools=tools,
        audit=audit,
        capability_service=capability_service,
    )


def evaluate_proposal(
    *,
    policy_path: Optional[Path],
    proposal_data: Dict[str, Any],
    audit_log_path: Path,
    base_dir: Path,
    session_id: Optional[str] = None,
    user_id: str = "local-user",
    role: str = "developer",
    tenant: str = "default",
    public_key_path: Optional[Path] = None,
    expected_audience: str = DEFAULT_AUDIENCE,
    capability_path: Optional[Path] = None,
):
    app = build_boundary_app(
        policy_path=policy_path,
        audit_log_path=audit_log_path,
        base_dir=base_dir,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
    )
    proposal = ToolProposal(tool=proposal_data["tool"], params=proposal_data.get("params", {}))
    session = SessionFacts(
        session_id=session_id or secrets.token_urlsafe(12),
        user_id=user_id,
        role=role,
        tenant=tenant,
    )
    capability = None
    if capability_path and Path(capability_path).exists():
        capability = CapabilityTicket(**load_json(Path(capability_path)))
    return app.handle(session=session, proposal=proposal, capability=capability)


def issue_capability(
    *,
    authority: str,
    audience: str,
    operation: str,
    session_id: str,
    scope: Dict[str, Any],
    params: Dict[str, Any],
    private_key_path: Path,
    public_key_path: Optional[Path] = None,
    key_id: str = "local-dev-key",
) -> CapabilityTicket:
    private_key_path, public_key_path = ensure_keypair(private_key_path, public_key_path)
    service = load_capability_service(
        private_key_path=private_key_path,
        public_key_path=public_key_path,
        expected_audience=audience,
    )
    return service.issue(
        key_id=key_id,
        authority=authority,
        audience=audience,
        operation=operation,
        session_id=session_id,
        scope=scope,
        params=params,
    )
