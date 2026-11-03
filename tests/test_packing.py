"""Tests for packing and chunking workflows."""
import json
import os
from pathlib import Path
import pytest
from b2chks import B2CHKS, pack, parse_size

def test_parse_size():
    assert parse_size("500b") == 500
    assert parse_size("500k") == 500 * 1024
    assert parse_size("100m") == 100 * 1024 * 1024
    assert parse_size("2g") == 2 * 1024 * 1024 * 1024
    with pytest.raises(ValueError):
        parse_size("invalid")

def test_pack_single_file_gzip(tmp_path):
    src = tmp_path / "data.bin"
    src.write_bytes(os.urandom(64 * 1024))
    dist = tmp_path / "dist"

    manifest_path = B2CHKS.pack(
        source=src,
        chunk_size="16k",
        output_dir=dist,
        compression="gzip",
    )
    assert manifest_path.exists()
    assert B2CHKS.verify(manifest=manifest_path)

def test_pack_directory_with_zstd(tmp_path):
    src_dir = tmp_path / "bundle"
    src_dir.mkdir()
    (src_dir / "item1.txt").write_text("Hello from Zstd bundle!")
    (src_dir / "item2.bin").write_bytes(b"\x01\x02\x03\x04" * 1000)
    dist = tmp_path / "dist_zstd"

    manifest_path = B2CHKS.pack(
        source=src_dir,
        chunk_size="8k",
        output_dir=dist,
        compression="zstd",
        encrypt_key="ZstdSecretKey",
    )
    assert manifest_path.exists()
    assert B2CHKS.verify(manifest=manifest_path)

def test_pack_with_cancel_token(tmp_path):
    from b2chks.exceptions import CancelledError
    src = tmp_path / "large.bin"
    src.write_bytes(os.urandom(100 * 1024))

    cancelled = False
    def should_cancel():
        nonlocal cancelled
        return cancelled

    cancelled = True
    with pytest.raises(CancelledError):
        B2CHKS.pack(
            source=src,
            chunk_size="4k",
            output_dir=tmp_path / "dist_cancelled",
            cancel_token=should_cancel,
        )
