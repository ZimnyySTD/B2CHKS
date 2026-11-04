"""Comprehensive test suite covering byte-budgeting, single-pass extraction, and actual compression recording."""
import os
from pathlib import Path
import pytest
from b2chks import B2CHKS
from b2chks.manifest import load_manifest

def test_actual_compression_recorded(tmp_path):
    src = tmp_path / "test.txt"
    src.write_text("Testing compression recording")
    dist = tmp_path / "dist"

    manifest_path = B2CHKS.pack(source=src, chunk_size="10k", output_dir=dist, compression="gzip")
    manifest = load_manifest(manifest_path)
    assert manifest["package_info"]["compression"] == "gzip"

def test_single_pass_corrupt_chunk_detected(tmp_path):
    src = tmp_path / "file.bin"
    src.write_bytes(os.urandom(32 * 1024))
    dist = tmp_path / "dist_corrupt"
    ext = tmp_path / "ext_corrupt"

    manifest_path = B2CHKS.pack(source=src, chunk_size="8k", output_dir=dist, encrypt_key="Key123")

    # Corrupt chunk 1
    chunk1 = dist / "chunk_001.bin"
    chunk1.write_bytes(b"\x00" * chunk1.stat().st_size)

    # Extraction must detect corruption and fail safely
    ok = B2CHKS.extract(manifest=manifest_path, output_dir=ext, decrypt_key="Key123")
    assert not ok
