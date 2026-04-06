"""Tests for JsonStore persistence."""

from pathlib import Path

from prompt_sentinel_control_plane.persistence import JsonStore


def test_append_and_list(tmp_path: Path):
    store = JsonStore(tmp_path / "test.jsonl")
    rec = store.append({"event": "test", "value": 42})
    assert "id" in rec
    assert "created_at" in rec

    records = store.list_all()
    assert len(records) == 1
    assert records[0]["event"] == "test"


def test_get_by_id(tmp_path: Path):
    store = JsonStore(tmp_path / "test.jsonl")
    rec = store.append({"event": "find_me"})
    found = store.get(rec["id"])
    assert found is not None
    assert found["event"] == "find_me"


def test_get_missing(tmp_path: Path):
    store = JsonStore(tmp_path / "test.jsonl")
    assert store.get("nonexistent") is None


def test_tenant_filter(tmp_path: Path):
    store = JsonStore(tmp_path / "test.jsonl")
    store.append({"tenant": "acme", "data": 1})
    store.append({"tenant": "other", "data": 2})
    store.append({"tenant": "acme", "data": 3})

    acme = store.list_all(tenant="acme")
    assert len(acme) == 2
    assert all(r["tenant"] == "acme" for r in acme)


def test_limit(tmp_path: Path):
    store = JsonStore(tmp_path / "test.jsonl")
    for i in range(10):
        store.append({"index": i})
    records = store.list_all(limit=3)
    assert len(records) == 3
    # Should return the last 3
    assert records[0]["index"] == 7


def test_list_empty_store(tmp_path: Path):
    store = JsonStore(tmp_path / "empty.jsonl")
    assert store.list_all() == []
