"""Alert primitives for Prompt_Sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class AlertRecord:
    event: str
    severity: str
    source: str
    summary: str
    session_id: str = ""
    tool_name: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event,
            "severity": self.severity,
            "source": self.source,
            "summary": self.summary,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "payload": self.payload,
        }
