"""FastAPI application for the Prompt_Sentinel control plane.

Provides persisted endpoints for policy bundles, capability approvals,
audit export, alerts, and threat vectors.  All mutating endpoints are
gated by bearer-token authentication when tokens are configured.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Query

from .auth import require_auth
from .models import (
    AlertRecord,
    AuditExportRequest,
    CapabilityApprovalRequest,
    PolicyBundleRecord,
    ThreatVectorRecord,
)
from .persistence import ControlPlaneStore

DATA_DIR = Path(os.environ.get("PROMPT_SENTINEL_DATA_DIR", ".prompt-sentinel-data"))
store = ControlPlaneStore(DATA_DIR)

app = FastAPI(title="Prompt Sentinel Control Plane", version="0.2.0")


# ── Health ───────────────────────────────────────────────────────────
@app.get("/healthz")
def healthz() -> Dict[str, str]:
    return {"status": "ok"}


# ── Policy Bundles ───────────────────────────────────────────────────
@app.post("/policy-bundles", status_code=201)
def create_policy_bundle(
    record: PolicyBundleRecord,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    persisted = store.policy_bundles.append(record.model_dump())
    return {"status": "created", "kind": "policy_bundle", "record": persisted}


@app.get("/policy-bundles")
def list_policy_bundles(
    tenant: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    records = store.policy_bundles.list_all(tenant=tenant, limit=limit)
    return {"kind": "policy_bundle_list", "count": len(records), "records": records}


@app.get("/policy-bundles/{record_id}")
def get_policy_bundle(
    record_id: str,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    rec = store.policy_bundles.get(record_id)
    if rec is None:
        return {"status": "not_found", "kind": "policy_bundle", "record_id": record_id}
    return {"kind": "policy_bundle", "record": rec}


# ── Approvals ────────────────────────────────────────────────────────
@app.post("/approvals", status_code=201)
def request_approval(
    request: CapabilityApprovalRequest,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    persisted = store.approvals.append(
        {**request.model_dump(), "status": "pending"}
    )
    return {"status": "created", "kind": "approval_request", "record": persisted}


@app.get("/approvals")
def list_approvals(
    tenant: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    records = store.approvals.list_all(tenant=tenant, limit=limit)
    return {"kind": "approval_list", "count": len(records), "records": records}


@app.get("/approvals/{record_id}")
def get_approval(
    record_id: str,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    rec = store.approvals.get(record_id)
    if rec is None:
        return {"status": "not_found", "kind": "approval", "record_id": record_id}
    return {"kind": "approval", "record": rec}


# ── Audit Exports ────────────────────────────────────────────────────
@app.post("/audit-exports", status_code=201)
def export_audit(
    request: AuditExportRequest,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    persisted = store.audit_exports.append(
        {**request.model_dump(), "status": "queued"}
    )
    return {"status": "created", "kind": "audit_export", "record": persisted}


@app.get("/audit-exports")
def list_audit_exports(
    tenant: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    records = store.audit_exports.list_all(tenant=tenant, limit=limit)
    return {"kind": "audit_export_list", "count": len(records), "records": records}


# ── Alerts ───────────────────────────────────────────────────────────
@app.post("/alerts", status_code=201)
def ingest_alert(
    alert: AlertRecord,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    persisted = store.alerts.append(alert.model_dump())
    return {"status": "created", "kind": "alert", "record": persisted}


@app.get("/alerts")
def list_alerts(
    tenant: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    records = store.alerts.list_all(tenant=tenant, limit=limit)
    return {"kind": "alert_list", "count": len(records), "records": records}


# ── Threat Vectors ───────────────────────────────────────────────────
@app.post("/threat-vectors", status_code=201)
def create_threat_vector(
    vector: ThreatVectorRecord,
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    persisted = store.threat_vectors.append(vector.model_dump())
    return {"status": "created", "kind": "threat_vector", "record": persisted}


@app.get("/threat-vectors")
def list_threat_vectors(
    limit: int = Query(200, ge=1, le=1000),
    _caller: str = Depends(require_auth),
) -> Dict[str, Any]:
    records = store.threat_vectors.list_all(limit=limit)
    return {"kind": "threat_vector_list", "count": len(records), "records": records}
