"""End-to-end proposal handling."""

from __future__ import annotations

from typing import Optional

from .audit import AuditChain
from .capability import CapabilityService
from .enforcer import PolicyEnforcer
from .models import CapabilityTicket, EnforcementDecision, SessionFacts, ToolProposal
from .tool_registry import ToolRegistry
from .utils import canonical_json, sha256_hex


class BoundaryApp:
    """Evaluate untrusted proposals, then execute only through trusted code."""

    def __init__(
        self,
        *,
        enforcer: PolicyEnforcer,
        tools: ToolRegistry,
        audit: AuditChain,
        capability_service: Optional[CapabilityService] = None,
    ) -> None:
        self.enforcer = enforcer
        self.tools = tools
        self.audit = audit
        self.capability_service = capability_service

    def handle(
        self,
        *,
        session: SessionFacts,
        proposal: ToolProposal,
        capability: Optional[CapabilityTicket] = None,
    ) -> EnforcementDecision:
        params_hash = sha256_hex(canonical_json(proposal.params))
        tool_metadata = self.enforcer.tool_metadata(proposal.tool)
        allowed, reason = self.enforcer.check_tool_call(
            session=session,
            tool=proposal.tool,
            params=proposal.params,
        )
        cap_required, cap_reason = self.enforcer.capability_required(
            tool=proposal.tool,
            params=proposal.params,
        )
        decision = EnforcementDecision(
            allowed=False,
            reason=reason,
            tool=proposal.tool,
            capability_required=cap_required,
            capability_reason=cap_reason,
            metadata={
                **tool_metadata,
                "session_id": session.session_id,
                "user_id": session.user_id,
                "policy_result": "pending",
                "capability_status": "required" if cap_required else "not-required",
                "params_hash": params_hash,
            },
        )

        if not allowed:
            decision.metadata["policy_result"] = "denied"
            decision.metadata["capability_status"] = "not-evaluated"
            self.audit.append(
                {
                    "event": "tool_call_denied",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": proposal.tool,
                    "reason": reason,
                    "policy_result": "denied",
                    "capability_status": "not-evaluated",
                    "params_hash": params_hash,
                    **tool_metadata,
                }
            )
            return decision

        if cap_required:
            if capability is None or self.capability_service is None:
                denial = "capability required but not provided"
                decision.metadata["policy_result"] = "denied"
                decision.metadata["capability_status"] = "missing"
                self.audit.append(
                    {
                        "event": "tool_call_denied",
                        "session_id": session.session_id,
                        "user_id": session.user_id,
                        "tool": proposal.tool,
                        "reason": denial,
                        "policy_result": "denied",
                        "capability_status": "missing",
                        "params_hash": params_hash,
                        **tool_metadata,
                    }
                )
                decision.reason = denial
                return decision
            ok, cap_message = self.capability_service.verify(
                capability,
                expected_session_id=session.session_id,
                expected_params=proposal.params,
            )
            if not ok:
                denial = f"invalid capability: {cap_message}"
                decision.metadata["policy_result"] = "denied"
                decision.metadata["capability_status"] = "invalid"
                self.audit.append(
                    {
                        "event": "tool_call_denied",
                        "session_id": session.session_id,
                        "user_id": session.user_id,
                        "tool": proposal.tool,
                        "reason": denial,
                        "policy_result": "denied",
                        "capability_status": "invalid",
                        "params_hash": params_hash,
                        **tool_metadata,
                    }
                )
                decision.reason = denial
                return decision
            decision.metadata["capability_status"] = "valid"

        try:
            result = self.tools.call(proposal.tool, proposal.params)
        except Exception as exc:
            decision.metadata["policy_result"] = "error"
            self.audit.append(
                {
                    "event": "tool_call_error",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": proposal.tool,
                    "reason": str(exc),
                    "policy_result": "error",
                    "capability_status": decision.metadata["capability_status"],
                    "params_hash": params_hash,
                    **tool_metadata,
                }
            )
            decision.reason = f"tool execution error: {exc}"
            return decision

        self.audit.append(
            {
                "event": "tool_call_allowed",
                "session_id": session.session_id,
                "user_id": session.user_id,
                "tool": proposal.tool,
                "policy_result": "allowed",
                "capability_status": decision.metadata["capability_status"],
                "params_hash": params_hash,
                **tool_metadata,
            }
        )
        decision.allowed = True
        decision.reason = "allowed"
        decision.result = result
        decision.metadata["policy_result"] = "allowed"
        return decision
