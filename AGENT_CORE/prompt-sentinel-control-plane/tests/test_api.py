"""Tests for control-plane API endpoints."""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_data(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PROMPT_SENTINEL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("PROMPT_SENTINEL_API_TOKENS", raising=False)
    # Re-import to pick up new env
    import importlib
    import prompt_sentinel_control_plane.app as app_mod
    from prompt_sentinel_control_plane.persistence import ControlPlaneStore

    app_mod.store = ControlPlaneStore(tmp_path / "data")
    yield


@pytest.fixture
def client():
    from prompt_sentinel_control_plane.app import app
    return TestClient(app)


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ── Policy Bundles ───────────────────────────────────────────────────
def test_create_and_list_policy_bundle(client):
    payload = {
        "policy_id": "pol-1",
        "version": "1.0",
        "tenant": "acme",
        "labels": ["production"],
        "bundle": {"tool_permissions": {"echo": {}}},
    }
    resp = client.post("/policy-bundles", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "created"
    record_id = body["record"]["id"]

    # List
    resp = client.get("/policy-bundles", params={"tenant": "acme"})
    assert resp.status_code == 200
    assert resp.json()["count"] == 1

    # Get by ID
    resp = client.get(f"/policy-bundles/{record_id}")
    assert resp.status_code == 200
    assert resp.json()["record"]["policy_id"] == "pol-1"


def test_get_missing_policy_bundle(client):
    resp = client.get("/policy-bundles/nonexistent")
    assert resp.json()["status"] == "not_found"


# ── Approvals ────────────────────────────────────────────────────────
def test_create_approval(client):
    payload = {
        "request_id": "req-1",
        "session_id": "sess-1",
        "tool": "sensitive_export",
        "params": {"dataset": "users"},
        "justification": "Quarterly report",
    }
    resp = client.post("/approvals", json=payload)
    assert resp.status_code == 201
    assert resp.json()["record"]["status"] == "pending"


def test_list_approvals(client):
    resp = client.get("/approvals")
    assert resp.status_code == 200
    assert "count" in resp.json()


# ── Alerts ───────────────────────────────────────────────────────────
def test_ingest_alert(client):
    payload = {
        "event": "prompt_override_detected",
        "severity": "high",
        "source": "claude-hook",
        "session_id": "s1",
        "tool_name": "Bash",
        "payload": {"pattern": "ignore previous instructions"},
    }
    resp = client.post("/alerts", json=payload)
    assert resp.status_code == 201

    resp = client.get("/alerts")
    assert resp.json()["count"] == 1


# ── Audit Exports ────────────────────────────────────────────────────
def test_create_audit_export(client):
    payload = {"destination": "s3://my-bucket/audits", "tenant": "acme", "format": "jsonl"}
    resp = client.post("/audit-exports", json=payload)
    assert resp.status_code == 201
    assert resp.json()["record"]["status"] == "queued"


# ── Threat Vectors ───────────────────────────────────────────────────
def test_create_threat_vector(client):
    payload = {
        "vector_id": "tv-1",
        "class_name": "prompt_injection",
        "summary": "Override instructions via user prompt",
        "fingerprints": ["ignore previous"],
        "redacted_examples": ["Ignore previous instructions and..."],
        "approved_for_sharing": False,
    }
    resp = client.post("/threat-vectors", json=payload)
    assert resp.status_code == 201

    resp = client.get("/threat-vectors")
    assert resp.json()["count"] == 1
