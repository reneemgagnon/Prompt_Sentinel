"""Tests for ToolRegistry."""

from pathlib import Path

import pytest

from prompt_sentinel.core.tool_registry import ToolError, ToolRegistry


def test_echo_tool(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    result = reg.call("echo", {"message": "hello"})
    assert result == {"echo": {"message": "hello"}}


def test_calc_sha256(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    result = reg.call("calc_sha256", {"text": "test"})
    assert "sha256_hex" in result
    assert len(result["sha256_hex"]) == 64


def test_file_read(tmp_path: Path):
    f = tmp_path / "readme.md"
    f.write_text("# Hello", encoding="utf-8")
    reg = ToolRegistry(base_dir=tmp_path)
    result = reg.call("file_read", {"path": "readme.md"})
    assert result == "# Hello"


def test_file_read_blocks_escape(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    with pytest.raises(ToolError, match="base_dir"):
        reg.call("file_read", {"path": "/etc/passwd"})


def test_file_read_missing_file(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    with pytest.raises(ToolError, match="missing"):
        reg.call("file_read", {"path": "no-such-file.txt"})


def test_file_read_too_large(tmp_path: Path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 65_000)
    reg = ToolRegistry(base_dir=tmp_path)
    with pytest.raises(ToolError, match="too large"):
        reg.call("file_read", {"path": "big.bin"})


def test_unknown_tool(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    with pytest.raises(ToolError, match="unknown tool"):
        reg.call("delete_everything", {})


def test_register_custom_tool(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    reg.register("greet", lambda params: f"Hello, {params['name']}!")
    result = reg.call("greet", {"name": "Alice"})
    assert result == "Hello, Alice!"


def test_list_tools(tmp_path: Path):
    reg = ToolRegistry(base_dir=tmp_path)
    tools = reg.list_tools()
    assert "echo" in tools
    assert "file_read" in tools
    assert "calc_sha256" in tools
    assert "sensitive_export" in tools
