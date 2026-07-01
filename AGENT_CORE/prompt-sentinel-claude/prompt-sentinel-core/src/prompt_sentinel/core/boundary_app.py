"""End-to-end proposal handling."""

from __future__ import annotations

from typing import Optional

from .audit import AuditChain
from .capability import CapabilityService
from .enforcer import PolicyEnforcer
from .mcp import analyze_tool_output
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
        execute: bool = True,
    ) -> EnforcementDecision:
        params_hash = sha256_hex(canonical_json(proposal.params))
        tool_metadata = self.enforcer.tool_metadata(proposal.tool, proposal.metadata)
        allowed, reason = self.enforcer.check_tool_call(
            session=session,
            tool=proposal.tool,
            params=proposal.params,
            metadata=proposal.metadata,
        )
        cap_required, cap_reason = self.enforcer.capability_required(
            tool=proposal.tool,
            params=proposal.params,
            metadata=proposal.metadata,
        )
        cap_context = self.enforcer.capability_context(tool=proposal.tool, metadata=proposal.metadata)
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
                expected_operation=cap_context["operation"],
                expected_scope=cap_context["scope"],
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

        if not execute:
            self.audit.append(
                {
                    "event": "tool_call_authorized",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": proposal.tool,
                    "policy_result": "authorized",
                    "capability_status": decision.metadata["capability_status"],
                    "params_hash": params_hash,
                    **tool_metadata,
                }
            )
            decision.allowed = True
            decision.reason = "authorized"
            decision.metadata["policy_result"] = "authorized"
            return decision

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

        output_risks = analyze_tool_output(result, self.enforcer.policy)
        if output_risks:
            decision.metadata["output_risks"] = output_risks
            self.audit.append(
                {
                    "event": "tool_output_flagged",
                    "session_id": session.session_id,
                    "user_id": session.user_id,
                    "tool": proposal.tool,
                    "risks": output_risks,
                    "params_hash": params_hash,
                    **tool_metadata,
                }
            )

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
