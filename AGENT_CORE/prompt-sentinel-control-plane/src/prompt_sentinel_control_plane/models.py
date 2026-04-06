"""Control-plane models."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PolicyBundleRecord(BaseModel):
    policy_id: str
    version: str
    tenant: str = "default"
    labels: List[str] = Field(default_factory=list)
    bundle: Dict[str, Any]


class CapabilityApprovalRequest(BaseModel):
    request_id: str
    session_id: str
    tool: str
    params: Dict[str, Any]
    justification: str


class AuditExportRequest(BaseModel):
    destination: str
    tenant: Optional[str] = None
    format: str = "jsonl"


class AlertRecord(BaseModel):
    event: str
    severity: str
    source: str
    session_id: Optional[str] = None
    tool_name: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


class ThreatVectorRecord(BaseModel):
    vector_id: str
    class_name: str
    summary: str
    fingerprints: List[str] = Field(default_factory=list)
    redacted_examples: List[str] = Field(default_factory=list)
    approved_for_sharing: bool = False
