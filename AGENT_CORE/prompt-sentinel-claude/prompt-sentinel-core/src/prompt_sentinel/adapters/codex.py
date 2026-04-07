"""Codex-oriented adapter helpers."""

from __future__ import annotations

from typing import Dict

from prompt_sentinel.core.models import EnforcementDecision


def decision_for_skill(decision: EnforcementDecision) -> Dict[str, object]:
    """Return a compact structure the Codex skill can explain to the model."""
    return {
        "allowed": decision.allowed,
        "tool": decision.tool,
        "reason": decision.reason,
        "capability_required": decision.capability_required,
        "capability_reason": decision.capability_reason,
    }
