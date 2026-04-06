"""Tests for AuditChain — append-only hash-chained log."""

import json
from pathlib import Path

from prompt_sentinel.core.audit import AuditChain


def test_append_creates_file(tmp_path: Path):
    chain = AuditChain(tmp_path / "audit.jsonl")
    record = chain.append({"event": "test", "tool": "echo"})
    assert "entry_hash" in record
    assert "prev_hash" in record
    assert "timestamp" in record
    assert (tmp_path / "audit.jsonl").exists()


def test_hash_chain_links(tmp_path: Path):
    chain = AuditChain(tmp_path / "audit.jsonl")
    r1 = chain.append({"event": "first"})
    r2 = chain.append({"event": "second"})
    assert r2["prev_hash"] == r1["entry_hash"]


def test_chain_resumes_from_disk(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    chain1 = AuditChain(path)
    r1 = chain1.append({"event": "first"})

    chain2 = AuditChain(path)
    r2 = chain2.append({"event": "resumed"})
    assert r2["prev_hash"] == r1["entry_hash"]


def test_initial_prev_hash_is_zero(tmp_path: Path):
    chain = AuditChain(tmp_path / "audit.jsonl")
    r1 = chain.append({"event": "genesis"})
    assert r1["prev_hash"] == "0" * 64


def test_entries_are_valid_jsonl(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(path)
    for i in range(5):
        chain.append({"event": f"entry_{i}"})

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
    for line in lines:
        record = json.loads(line)
        assert "entry_hash" in record
        assert "prev_hash" in record


def test_tamper_detection(tmp_path: Path):
    """Verify that modifying an entry breaks the hash chain."""
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(path)
    chain.append({"event": "first"})
    chain.append({"event": "second"})
    r3 = chain.append({"event": "third"})

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    records = [json.loads(line) for line in lines]

    # Tamper with the second entry
    records[1]["event"] = "TAMPERED"
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )

    # The third entry's prev_hash should no longer match the (tampered) second
    tampered_lines = path.read_text(encoding="utf-8").strip().splitlines()
    tampered_records = [json.loads(line) for line in tampered_lines]
    from prompt_sentinel.core.utils import canonical_json, sha256_hex

    recomputed = sha256_hex(
        canonical_json({k: v for k, v in tampered_records[1].items() if k != "entry_hash"})
    )
    assert recomputed != tampered_records[1]["entry_hash"], "tampered entry hash should not match"
