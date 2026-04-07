"""Tests for audit log exporters."""

import json
from pathlib import Path

from prompt_sentinel.core.exporters import (
    ExportBatch,
    FileExporter,
    StdoutExporter,
    WebhookExporter,
    create_exporter,
    export_audit_log,
    read_audit_log,
)


def _write_audit(path: Path, records: list) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


SAMPLE_RECORDS = [
    {"event": "tool_call_allowed", "tool": "echo", "timestamp": 1000},
    {"event": "tool_call_denied", "tool": "rm", "timestamp": 2000},
    {"event": "tool_call_allowed", "tool": "file_read", "timestamp": 3000},
]


# ── ExportBatch ──────────────────────────────────────────────────────
def test_batch_to_jsonl():
    batch = ExportBatch(SAMPLE_RECORDS)
    jsonl = batch.to_jsonl()
    lines = jsonl.strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["event"] == "tool_call_allowed"


def test_batch_to_payload():
    batch = ExportBatch(SAMPLE_RECORDS, source="test")
    payload = batch.to_payload()
    assert payload["source"] == "test"
    assert payload["count"] == 3


# ── FileExporter ─────────────────────────────────────────────────────
def test_file_exporter(tmp_path: Path):
    dest = tmp_path / "export" / "audit.jsonl"
    exporter = FileExporter(dest)
    result = exporter.export(ExportBatch(SAMPLE_RECORDS))
    assert result["sink"] == "file"
    assert result["count"] == 3
    assert dest.exists()
    lines = dest.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3


def test_file_exporter_appends(tmp_path: Path):
    dest = tmp_path / "audit.jsonl"
    exporter = FileExporter(dest)
    exporter.export(ExportBatch(SAMPLE_RECORDS[:1]))
    exporter.export(ExportBatch(SAMPLE_RECORDS[1:]))
    lines = dest.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3


# ── StdoutExporter ───────────────────────────────────────────────────
def test_stdout_exporter(capsys):
    exporter = StdoutExporter()
    result = exporter.export(ExportBatch(SAMPLE_RECORDS))
    assert result["sink"] == "stdout"
    captured = capsys.readouterr()
    assert "tool_call_allowed" in captured.out


# ── read_audit_log ───────────────────────────────────────────────────
def test_read_audit_log(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    _write_audit(path, SAMPLE_RECORDS)
    records = read_audit_log(path)
    assert len(records) == 3


def test_read_audit_log_with_filter(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    _write_audit(path, SAMPLE_RECORDS)
    records = read_audit_log(path, after_timestamp=1500)
    assert len(records) == 2
    assert all(r["timestamp"] > 1500 for r in records)


def test_read_audit_log_missing_file(tmp_path: Path):
    records = read_audit_log(tmp_path / "nonexistent.jsonl")
    assert records == []


# ── create_exporter factory ──────────────────────────────────────────
def test_create_file_exporter(tmp_path: Path):
    exporter = create_exporter(f"file://{tmp_path}/out.jsonl")
    assert isinstance(exporter, FileExporter)


def test_create_stdout_exporter():
    exporter = create_exporter("stdout")
    assert isinstance(exporter, StdoutExporter)


def test_create_webhook_exporter():
    exporter = create_exporter("https://splunk.example.com/hec")
    assert isinstance(exporter, WebhookExporter)


def test_create_exporter_invalid_scheme():
    import pytest
    with pytest.raises(ValueError, match="Unsupported"):
        create_exporter("ftp://example.com/audit")


# ── End-to-end export_audit_log ──────────────────────────────────────
def test_export_audit_log_to_file(tmp_path: Path):
    audit_path = tmp_path / "source.jsonl"
    _write_audit(audit_path, SAMPLE_RECORDS)
    dest = tmp_path / "dest.jsonl"
    result = export_audit_log(audit_path, f"file://{dest}")
    assert result["count"] == 3
    assert dest.exists()


def test_export_empty_audit(tmp_path: Path):
    audit_path = tmp_path / "empty.jsonl"
    result = export_audit_log(audit_path, "stdout")
    assert result["status"] == "empty"
