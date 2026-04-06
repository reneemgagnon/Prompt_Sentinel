"""File-backed JSON persistence for the control plane.

Stores records as newline-delimited JSON files, one per resource type.
Suitable for single-node and developer deployments.  Swap with a database
adapter (Postgres, SQLite, DynamoDB) for production multi-node setups.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


class JsonStore:
    """Append-only JSONL store with basic query support."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(record)
        record.setdefault("id", uuid.uuid4().hex)
        record.setdefault("created_at", int(time.time()))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def list_all(self, *, tenant: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        records: List[Dict[str, Any]] = []
        with self._lock:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    if tenant and rec.get("tenant") != tenant:
                        continue
                    records.append(rec)
        return records[-limit:]

    def get(self, record_id: str) -> Optional[Dict[str, Any]]:
        for rec in self.list_all():
            if rec.get("id") == record_id:
                return rec
        return None


class ControlPlaneStore:
    """Aggregate store for all control-plane resource types."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.policy_bundles = JsonStore(self.data_dir / "policy_bundles.jsonl")
        self.approvals = JsonStore(self.data_dir / "approvals.jsonl")
        self.audit_exports = JsonStore(self.data_dir / "audit_exports.jsonl")
        self.alerts = JsonStore(self.data_dir / "alerts.jsonl")
        self.threat_vectors = JsonStore(self.data_dir / "threat_vectors.jsonl")
