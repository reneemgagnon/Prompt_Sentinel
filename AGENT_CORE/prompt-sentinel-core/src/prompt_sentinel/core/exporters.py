"""Audit log export connectors.

Each exporter reads audit JSONL and forwards entries to an external sink.
Supported destinations:

  - file://  — copy to another JSONL path (archive, shared mount)
  - https:// — POST batches to a webhook (Splunk HEC, Datadog, generic SIEM)
  - s3://    — upload to S3-compatible storage (AWS, MinIO, R2)
  - stdout   — print to stdout (debugging / piping)
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class ExportBatch:
    """A batch of audit records ready for export."""

    def __init__(self, records: List[Dict[str, Any]], source: str = "prompt-sentinel"):
        self.records = records
        self.source = source
        self.exported_at = int(time.time())

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in self.records) + "\n"

    def to_payload(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "exported_at": self.exported_at,
            "count": len(self.records),
            "records": self.records,
        }


class AuditExporter(ABC):
    """Base class for audit export sinks."""

    @abstractmethod
    def export(self, batch: ExportBatch) -> Dict[str, Any]:
        """Export a batch and return a status dict."""


class FileExporter(AuditExporter):
    """Export audit records to a local JSONL file."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def export(self, batch: ExportBatch) -> Dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(batch.to_jsonl())
        return {"sink": "file", "path": str(self.path), "count": len(batch.records)}


class StdoutExporter(AuditExporter):
    """Print audit records to stdout."""

    def export(self, batch: ExportBatch) -> Dict[str, Any]:
        print(batch.to_jsonl(), end="")
        return {"sink": "stdout", "count": len(batch.records)}


class WebhookExporter(AuditExporter):
    """POST audit batches to an HTTPS webhook endpoint.

    Compatible with:
      - Splunk HTTP Event Collector (HEC)
      - Datadog Log Intake
      - Generic SIEM webhook receivers
    """

    def __init__(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 30,
    ):
        self.url = url
        self.headers = headers or {}
        self.timeout_seconds = timeout_seconds

    def export(self, batch: ExportBatch) -> Dict[str, Any]:
        import urllib.request

        payload = json.dumps(batch.to_payload(), ensure_ascii=False).encode("utf-8")
        req_headers = {
            "Content-Type": "application/json",
            **self.headers,
        }
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers=req_headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return {
                "sink": "webhook",
                "url": self.url,
                "error": str(exc),
                "count": len(batch.records),
            }
        return {
            "sink": "webhook",
            "url": self.url,
            "status": status,
            "count": len(batch.records),
            "response": body[:500],
        }


class S3Exporter(AuditExporter):
    """Upload audit batches to S3-compatible object storage.

    Requires boto3 at runtime (not a hard dependency of the core package).
    Works with AWS S3, MinIO, Cloudflare R2, etc.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "prompt-sentinel/audit",
        *,
        endpoint_url: Optional[str] = None,
        region: str = "us-east-1",
    ):
        self.bucket = bucket
        self.prefix = prefix.rstrip("/")
        self.endpoint_url = endpoint_url
        self.region = region

    def export(self, batch: ExportBatch) -> Dict[str, Any]:
        try:
            import boto3
        except ImportError:
            return {
                "sink": "s3",
                "error": "boto3 not installed — run: pip install boto3",
                "count": len(batch.records),
            }
        key = f"{self.prefix}/{batch.exported_at}.jsonl"
        client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            region_name=self.region,
        )
        client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=batch.to_jsonl().encode("utf-8"),
            ContentType="application/x-ndjson",
        )
        return {
            "sink": "s3",
            "bucket": self.bucket,
            "key": key,
            "count": len(batch.records),
        }


def create_exporter(destination: str, **kwargs) -> AuditExporter:
    """Factory that creates an exporter from a destination URI.

    Examples:
        create_exporter("file:///var/log/sentinel/audit.jsonl")
        create_exporter("https://splunk.corp.com:8088/services/collector")
        create_exporter("s3://my-bucket/audit-logs")
        create_exporter("stdout")
    """
    if destination == "stdout":
        return StdoutExporter()

    parsed = urlparse(destination)

    if parsed.scheme == "file" or (not parsed.scheme and not parsed.netloc):
        path = parsed.path or destination
        return FileExporter(Path(path))

    if parsed.scheme in ("http", "https"):
        return WebhookExporter(destination, **kwargs)

    if parsed.scheme == "s3":
        bucket = parsed.netloc
        prefix = parsed.path.lstrip("/") or "prompt-sentinel/audit"
        return S3Exporter(bucket, prefix, **kwargs)

    raise ValueError(f"Unsupported export destination scheme: {parsed.scheme!r}")


def read_audit_log(path: Path, *, after_timestamp: Optional[int] = None) -> List[Dict[str, Any]]:
    """Read audit JSONL and optionally filter to entries after a timestamp."""
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if after_timestamp and record.get("timestamp", 0) <= after_timestamp:
                continue
            records.append(record)
    return records


def export_audit_log(
    audit_path: Path,
    destination: str,
    *,
    after_timestamp: Optional[int] = None,
    **exporter_kwargs,
) -> Dict[str, Any]:
    """One-shot: read audit log, create exporter, send batch."""
    records = read_audit_log(audit_path, after_timestamp=after_timestamp)
    if not records:
        return {"status": "empty", "count": 0}
    exporter = create_exporter(destination, **exporter_kwargs)
    batch = ExportBatch(records)
    return exporter.export(batch)
