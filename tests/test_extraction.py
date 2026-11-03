"""Tests for extraction and reassembly."""
import os
from pathlib import Path
import pytest
from b2chks import B2CHKS
from b2chks.exceptions import DecryptionError

def test_extract_unencrypted_file(tmp_path):
    src = tmp_path / "original.txt"
    content = "Extract test content unencrypted\n" * 500
    src.write_text(content)

    dist = tmp_path / "dist"
    ext = tmp_path / "extracted"

    manifest = B2CHKS.pack(source=src, chunk_size="4k", output_dir=dist)
    assert B2CHKS.extract(manifest=manifest, output_dir=ext)
    assert (ext / "original.txt").read_text() == content

def test_extract_encrypted_directory_wrong_key(tmp_path):
    src_dir = tmp_path / "secure_dir"
    src_dir.mkdir()
    (src_dir / "secret.txt").write_text("Confidential")

    dist = tmp_path / "dist_sec"
    ext = tmp_path / "ext_sec"

    manifest = B2CHKS.pack(
        source=src_dir,
        chunk_size="2k",
        output_dir=dist,
        encrypt_key="CorrectPassword",
    )

    # Wrong key fails
    ok = B2CHKS.extract(manifest=manifest, output_dir=ext, decrypt_key="WrongPassword")
    assert not ok

    # Correct key succeeds
    ok2 = B2CHKS.extract(manifest=manifest, output_dir=ext, decrypt_key="CorrectPassword")
    assert ok2
    assert (ext / "secure_dir" / "secret.txt").read_text() == "Confidential"
