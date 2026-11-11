"""Tests for --nochunks compression and extraction."""
import os
from pathlib import Path
import pytest
from b2chks import B2CHKS
from b2chks.manifest import load_manifest

def test_pack_file_nochunks(tmp_path):
    src = tmp_path / "simple.txt"
    src.write_text("Hello without chunks!")
    dist = tmp_path / "dist"
    ext = tmp_path / "ext"

    manifest_path = B2CHKS.pack(source=src, nochunks=True, output_dir=dist)
    manifest = load_manifest(manifest_path)
    assert manifest["package_info"]["total_chunks"] == 1
    assert manifest["package_info"]["nochunks"] is True
    assert (dist / "chunk_000.bin").exists()
    assert not (dist / "chunk_001.bin").exists()

    assert B2CHKS.verify(manifest=manifest_path)
    assert B2CHKS.extract(manifest=manifest_path, output_dir=ext)
    assert (ext / "simple.txt").read_text() == "Hello without chunks!"

def test_pack_directory_nochunks_encrypted(tmp_path):
    src_dir = tmp_path / "folder"
    src_dir.mkdir()
    (src_dir / "f1.bin").write_bytes(os.urandom(10000))
    dist = tmp_path / "dist_enc"
    ext = tmp_path / "ext_enc"

    manifest_path = B2CHKS.pack(
        source=src_dir,
        nochunks=True,
        output_dir=dist,
        encrypt_key="NoChunkPass",
    )
    manifest = load_manifest(manifest_path)
    assert manifest["package_info"]["total_chunks"] == 1

    assert B2CHKS.extract(manifest=manifest_path, output_dir=ext, decrypt_key="NoChunkPass")
    assert (ext / "folder" / "f1.bin").read_bytes() == (src_dir / "f1.bin").read_bytes()

def test_cli_pack_nochunks(tmp_path):
    import subprocess, sys
    src = tmp_path / "cli_doc.txt"
    src.write_text("CLI test without chunks")
    dist = tmp_path / "cli_dist"

    res = subprocess.run(
        [sys.executable, "b2chks.py", "pack", str(src), "--nochunks", "--output-dir", str(dist)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert (dist / "manifest.json").exists()
    assert (dist / "chunk_000.bin").exists()
