"""Trusted tool registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List

from .utils import sha256_hex


class ToolError(Exception):
    """Raised when a trusted tool fails or is called incorrectly."""


class ToolRegistry:
    """Register and execute trusted tool implementations."""

    def __init__(self, *, base_dir: Path):
        self.base_dir = Path(base_dir).resolve()
        self._tools: Dict[str, Callable[[Dict[str, Any]], Any]] = {
            "file_read": self._file_read,
            "calc_sha256": self._calc_sha256,
            "echo": self._echo,
            "sensitive_export": self._sensitive_export_stub,
        }

    def register(self, name: str, fn: Callable[[Dict[str, Any]], Any]) -> None:
        self._tools[name] = fn

    def list_tools(self) -> List[str]:
        return sorted(self._tools.keys())

    def call(self, name: str, params: Dict[str, Any]) -> Any:
        if name not in self._tools:
            raise ToolError(f"unknown tool: {name}")
        return self._tools[name](params)

    def _file_read(self, params: Dict[str, Any]) -> str:
        path = params.get("path")
        if not isinstance(path, str) or not path:
            raise ToolError("file_read requires 'path'")
        candidate = Path(path).expanduser()
        candidate = (self.base_dir / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        if self.base_dir not in candidate.parents and candidate != self.base_dir:
            raise ToolError("file_read blocked by base_dir constraint")
        if not candidate.exists() or not candidate.is_file():
            raise ToolError("file_read target missing or not a file")
        data = candidate.read_bytes()
        if len(data) > 64_000:
            raise ToolError("file_read: file too large")
        return data.decode("utf-8", errors="replace")

    def _calc_sha256(self, params: Dict[str, Any]) -> Dict[str, str]:
        text = params.get("text", "")
        if not isinstance(text, str):
            raise ToolError("calc_sha256 requires 'text' as string")
        return {"sha256_hex": sha256_hex(text.encode("utf-8"))}

    def _echo(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"echo": params}

    def _sensitive_export_stub(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "export_complete", "details": "stubbed_export", "request": params}
