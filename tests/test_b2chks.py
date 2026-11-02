import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import b2chks


def test_parse_size():
    assert b2chks.parse_size("100") == 100
    assert b2chks.parse_size("500b") == 500
    assert b2chks.parse_size("500k") == 500 * 1024
    assert b2chks.parse_size("100kb") == 100 * 1024
    assert b2chks.parse_size("500m") == 500 * 1024 * 1024
    assert b2chks.parse_size("2g") == 2 * 1024 * 1024 * 1024
    with pytest.raises(ValueError):
        b2chks.parse_size("invalid")
    with pytest.raises(ValueError):
        b2chks.parse_size("-50m")
    with pytest.raises(ValueError):
        b2chks.parse_size("")


def test_keygen(tmp_path):
    priv, pub = b2chks.generate_keypair("arcxan", str(tmp_path))
    assert Path(priv).exists()
    assert Path(pub).exists()

    with open(priv, "r") as f:
        assert "BEGIN PRIVATE KEY" in f.read()
    with open(pub, "r") as f:
        assert "BEGIN PUBLIC KEY" in f.read()


def test_pack_and_extract_single_file_unencrypted(tmp_path):
    # Setup test file with uncompressible data so compressed size exceeds chunk_size
    src_file = tmp_path / "sample.bin"
    original_content = os.urandom(64 * 1024)  # 64KB random bytes
    src_file.write_bytes(original_content)

    # Keygen
    priv, pub = b2chks.generate_keypair("tester", str(tmp_path / "keys"))

    dist_dir = tmp_path / "dist"
    extract_dir = tmp_path / "extracted"

    # Pack with small chunk size so multiple chunks are produced
    manifest_path = b2chks.pack(
        source=str(src_file),
        chunk_size_str="16k",
        output_dir=str(dist_dir),
        private_key_path=priv,
        author="tester",
    )

    assert manifest_path.exists()
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    assert manifest["protocol"] == "b2chks"
    assert manifest["package_info"]["name"] == "sample.bin"
    assert manifest["package_info"]["source_type"] == "file"
    assert manifest["package_info"]["total_size_bytes"] == len(original_content)
    assert not manifest["package_info"]["encrypted"]
    assert manifest["security"]["developer_id"] == "tester"
    assert len(manifest["security"]["signature"]) > 0
    assert len(manifest["chunks"]) > 1

    # Verify
    assert b2chks.verify(str(manifest_path), public_key_path=pub)

    # Extract
    success = b2chks.extract(str(manifest_path), output_dir=str(extract_dir), public_key_path=pub)
    assert success

    extracted_file = extract_dir / "sample.bin"
    assert extracted_file.exists()
    assert extracted_file.read_bytes() == original_content


def test_pack_and_extract_directory_encrypted(tmp_path):
    # Setup directory structure
    src_dir = tmp_path / "my_project"
    src_dir.mkdir()
    (src_dir / "subfolder").mkdir()
    (src_dir / "file1.txt").write_text("Hello World!")
    (src_dir / "subfolder" / "data.bin").write_bytes(b"\x00\x01\x02\x03\xff" * 4000)

    dist_dir = tmp_path / "dist_dir"
    extract_dir = tmp_path / "extracted_dir"

    # Pack directory with encryption
    passphrase = "UltraSecretPassphrase123"
    manifest_path = b2chks.pack(
        source=str(src_dir),
        chunk_size_str="8k",
        output_dir=str(dist_dir),
        encrypt_key=passphrase,
    )

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    assert manifest["package_info"]["source_type"] == "directory"
    assert manifest["package_info"]["encrypted"] is True
    assert "encryption" in manifest
    assert manifest["encryption"]["algorithm"] == "AES-256-GCM"

    # Verify
    assert b2chks.verify(str(manifest_path))

    # Extraction with wrong key should fail
    fail_success = b2chks.extract(
        str(manifest_path),
        output_dir=str(extract_dir),
        decrypt_key="WrongPassword",
    )
    assert not fail_success

    # Extraction with correct key
    ok = b2chks.extract(
        str(manifest_path),
        output_dir=str(extract_dir),
        decrypt_key=passphrase,
    )
    assert ok

    extracted_project = extract_dir / "my_project"
    assert extracted_project.is_dir()
    assert (extracted_project / "file1.txt").read_text() == "Hello World!"
    assert (extracted_project / "subfolder" / "data.bin").read_bytes() == (b"\x00\x01\x02\x03\xff" * 4000)


def test_verification_corrupted_and_missing_chunk(tmp_path):
    src_file = tmp_path / "dummy.dat"
    src_file.write_bytes(os.urandom(30 * 1024))

    dist_dir = tmp_path / "dist"
    manifest_path = b2chks.pack(
        source=str(src_file),
        chunk_size_str="8k",
        output_dir=str(dist_dir),
    )

    assert b2chks.verify(str(manifest_path))

    # Corrupt chunk_000.bin
    chunk0 = dist_dir / "chunk_000.bin"
    chunk0.write_bytes(b"CORRUPTED_BYTES" + chunk0.read_bytes())
    assert not b2chks.verify(str(manifest_path))

    # Remove chunk_001.bin
    chunk1 = dist_dir / "chunk_001.bin"
    chunk1.unlink()
    assert not b2chks.verify(str(manifest_path))


def test_verification_tampered_manifest_signature(tmp_path):
    src_file = tmp_path / "dummy2.dat"
    src_file.write_bytes(b"B" * 20000)
    priv, pub = b2chks.generate_keypair("author1", str(tmp_path / "keys"))

    dist_dir = tmp_path / "dist"
    manifest_path = b2chks.pack(
        source=str(src_file),
        chunk_size_str="8k",
        output_dir=str(dist_dir),
        private_key_path=priv,
        author="author1",
    )

    assert b2chks.verify(str(manifest_path), public_key_path=pub)

    # Tamper with manifest package_info
    with open(manifest_path, "r") as f:
        data = json.load(f)
    data["package_info"]["name"] = "tampered_name.dat"
    with open(manifest_path, "w") as f:
        json.dump(data, f)

    assert not b2chks.verify(str(manifest_path), public_key_path=pub)


def test_cli_subcommands(tmp_path):
    # Test keygen CLI
    res = subprocess.run(
        [sys.executable, "b2chks.py", "keygen", "--author", "cli_tester", "--out-dir", str(tmp_path / "cli_keys")],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert (tmp_path / "cli_keys" / "private.pem").exists()
    assert (tmp_path / "cli_keys" / "public.pem").exists()

    # Test pack CLI requires chunk-size
    test_file = tmp_path / "cli_test.txt"
    test_file.write_text("Testing CLI execution")

    res = subprocess.run(
        [sys.executable, "b2chks.py", "pack", str(test_file)],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "required" in res.stderr.lower() or "--chunk-size" in res.stderr.lower()

    # Test pack CLI success
    out_dir = tmp_path / "cli_dist"
    res = subprocess.run(
        [
            sys.executable,
            "b2chks.py",
            "pack",
            str(test_file),
            "--chunk-size",
            "1k",
            "--output-dir",
            str(out_dir),
            "--private-key",
            str(tmp_path / "cli_keys" / "private.pem"),
            "--author",
            "cli_tester",
            "--encrypt-key",
            "cli_pass",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    manifest = out_dir / "manifest.json"
    assert manifest.exists()

    # Test verify CLI success
    res = subprocess.run(
        [
            sys.executable,
            "b2chks.py",
            "verify",
            str(manifest),
            "--public-key",
            str(tmp_path / "cli_keys" / "public.pem"),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0

    # Test extract CLI success
    ext_dir = tmp_path / "cli_ext"
    res = subprocess.run(
        [
            sys.executable,
            "b2chks.py",
            "extract",
            str(manifest),
            "--output-dir",
            str(ext_dir),
            "--decrypt-key",
            "cli_pass",
            "--public-key",
            str(tmp_path / "cli_keys" / "public.pem"),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert (ext_dir / "cli_test.txt").read_text() == "Testing CLI execution"
