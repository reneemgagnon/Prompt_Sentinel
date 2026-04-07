"""Tamper-evident JSONL audit log."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from .utils import canonical_json, sha256_hex


class AuditChain:
    """Append-only hash-chained audit log."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last_entry = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last_entry = json.loads(line)
        return str(last_entry.get("entry_hash")) if last_entry else "0" * 64

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        record = dict(entry)
        record["timestamp"] = int(time.time())
        record["prev_hash"] = self._last_hash
        entry_hash = sha256_hex(canonical_json({k: v for k, v in record.items() if k != "entry_hash"}))
        record["entry_hash"] = entry_hash
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._last_hash = entry_hash
        return record
