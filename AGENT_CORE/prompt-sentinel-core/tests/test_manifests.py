"""Tests for InstructionManifest."""

from pathlib import Path

from prompt_sentinel.core.manifests import InstructionManifest


def test_fingerprint_existing_file(tmp_path: Path):
    f = tmp_path / "test.md"
    f.write_text("hello", encoding="utf-8")
    fp = InstructionManifest.fingerprint(f)
    assert len(fp) == 64  # sha256 hex


def test_fingerprint_missing_file(tmp_path: Path):
    fp = InstructionManifest.fingerprint(tmp_path / "nonexistent.md")
    assert fp == "missing"


def test_build_manifest(tmp_path: Path):
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_text("alpha", encoding="utf-8")
    b.write_text("beta", encoding="utf-8")
    manifest = InstructionManifest.build([a, b])
    assert len(manifest) == 2
    assert all(len(v) == 64 for v in manifest.values())


def test_verify_no_changes(tmp_path: Path):
    f = tmp_path / "stable.md"
    f.write_text("unchanged", encoding="utf-8")
    manifest = InstructionManifest.build([f])
    mismatches = InstructionManifest.verify(manifest)
    assert mismatches == {}


def test_verify_detects_change(tmp_path: Path):
    f = tmp_path / "mutable.md"
    f.write_text("original", encoding="utf-8")
    manifest = InstructionManifest.build([f])
    f.write_text("TAMPERED", encoding="utf-8")
    mismatches = InstructionManifest.verify(manifest)
    assert str(f) in mismatches
    assert mismatches[str(f)]["expected"] != mismatches[str(f)]["actual"]


def test_verify_detects_deletion(tmp_path: Path):
    f = tmp_path / "gone.md"
    f.write_text("here now", encoding="utf-8")
    manifest = InstructionManifest.build([f])
    f.unlink()
    mismatches = InstructionManifest.verify(manifest)
    assert str(f) in mismatches
    assert mismatches[str(f)]["actual"] == "missing"
