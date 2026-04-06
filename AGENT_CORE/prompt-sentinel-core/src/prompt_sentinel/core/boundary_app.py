"""End-to-end proposal handling."""

from __future__ import annotations

from typing import Optional

from .audit import AuditChain
from .capability import CapabilityService
from .enforcer import PolicyEnforcer
from .models import CapabilityTicket, EnforcementDecision, SessionFacts, ToolProposal
from .tool_registry import ToolRegistry


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
        )

        if not allowed:
            self.audit.append(
                {
                    "event": "tool_call_denied",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": proposal.tool,
                    "reason": reason,
                }
            )
            return decision

        if cap_required:
            if capability is None or self.capability_service is None:
                denial = "capability required but not provided"
                self.audit.append(
                    {
                        "event": "tool_call_denied",
                        "session_id": session.session_id,
                        "user_id": session.user_id,
                        "tool": proposal.tool,
                        "reason": denial,
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
                self.audit.append(
                    {
                        "event": "tool_call_denied",
                        "session_id": session.session_id,
                        "user_id": session.user_id,
                        "tool": proposal.tool,
                        "reason": denial,
                    }
                )
                decision.reason = denial
                return decision

        try:
            result = self.tools.call(proposal.tool, proposal.params)
        except Exception as exc:
            self.audit.append(
                {
                    "event": "tool_call_error",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": proposal.tool,
                    "reason": str(exc),
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
            }
        )
        decision.allowed = True
        decision.reason = "allowed"
        decision.result = result
        return decision
