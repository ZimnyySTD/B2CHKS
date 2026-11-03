"""Integration tests for B2CHKS CLI and top-level workflows."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import b2chks
import install
from b2chks import B2CHKS


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

    with open(priv, "r", encoding="utf-8") as f:
        assert "BEGIN PRIVATE KEY" in f.read()
    with open(pub, "r", encoding="utf-8") as f:
        assert "BEGIN PUBLIC KEY" in f.read()


def test_anti_brute_force_scrypt_kdf():
    salt = os.urandom(16)
    passphrase = "UltraSecurePassword!"
    key_scrypt = b2chks.derive_aes_key(passphrase, salt, kdf_name="scrypt")
    assert len(key_scrypt) == 32

    key_pbkdf2 = b2chks.derive_aes_key(passphrase, salt, kdf_name="pbkdf2")
    assert len(key_pbkdf2) == 32
    assert key_scrypt != key_pbkdf2


def test_sdk_api_and_progress_callback(tmp_path):
    src_file = tmp_path / "sdk_test.dat"
    content = b"SDK embed test " * 2000
    src_file.write_bytes(content)

    progress_events = []

    def on_progress(current, total, stage):
        progress_events.append((current, total, stage))

    priv, pub = B2CHKS.keygen(author="sdk_dev", out_dir=str(tmp_path / "keys"))
    dist_dir = tmp_path / "sdk_dist"
    ext_dir = tmp_path / "sdk_ext"

    manifest_path = B2CHKS.pack(
        source=str(src_file),
        chunk_size="4k",
        output_dir=str(dist_dir),
        encrypt_key="SdkPassphrase",
        private_key=priv,
        author="sdk_dev",
        progress_callback=on_progress,
    )

    assert manifest_path.exists()
    assert len(progress_events) > 0
    assert any(stage == "chunking" for _, _, stage in progress_events)

    assert B2CHKS.verify(str(manifest_path), public_key=pub)

    ok = B2CHKS.extract(str(manifest_path), output_dir=str(ext_dir), decrypt_key="SdkPassphrase", public_key=pub)
    assert ok
    assert (ext_dir / "sdk_test.dat").read_bytes() == content


def test_pack_and_extract_single_file_unencrypted(tmp_path):
    src_file = tmp_path / "sample.bin"
    original_content = os.urandom(64 * 1024)
    src_file.write_bytes(original_content)

    priv, pub = b2chks.generate_keypair("tester", str(tmp_path / "keys"))
    dist_dir = tmp_path / "dist"
    extract_dir = tmp_path / "extracted"

    manifest_path = b2chks.pack(
        source=str(src_file),
        chunk_size_str="16k",
        output_dir=str(dist_dir),
        private_key_path=priv,
        author="tester",
    )

    assert manifest_path.exists()
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["protocol"] == "b2chks"
    assert manifest["package_info"]["name"] == "sample.bin"
    assert manifest["package_info"]["source_type"] == "file"
    assert manifest["package_info"]["total_size_bytes"] == len(original_content)
    assert not manifest["package_info"]["encrypted"]
    assert manifest["security"]["developer_id"] == "tester"
    assert len(manifest["security"]["signature"]) > 0
    assert len(manifest["chunks"]) > 1

    assert b2chks.verify(str(manifest_path), public_key_path=pub)

    success = b2chks.extract(str(manifest_path), output_dir=str(extract_dir), public_key_path=pub)
    assert success

    extracted_file = extract_dir / "sample.bin"
    assert extracted_file.exists()
    assert extracted_file.read_bytes() == original_content


def test_pack_and_extract_directory_encrypted(tmp_path):
    src_dir = tmp_path / "my_project"
    src_dir.mkdir()
    (src_dir / "subfolder").mkdir()
    (src_dir / "file1.txt").write_text("Hello World!", encoding="utf-8")
    (src_dir / "subfolder" / "data.bin").write_bytes(b"\x00\x01\x02\x03\xff" * 4000)

    dist_dir = tmp_path / "dist_dir"
    extract_dir = tmp_path / "extracted_dir"

    passphrase = "UltraSecretPassphrase123"
    manifest_path = b2chks.pack(
        source=str(src_dir),
        chunk_size_str="8k",
        output_dir=str(dist_dir),
        encrypt_key=passphrase,
    )

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["package_info"]["source_type"] == "directory"
    assert manifest["package_info"]["encrypted"] is True
    assert "encryption" in manifest
    assert manifest["encryption"]["algorithm"] == "AES-256-GCM"
    assert manifest["encryption"]["kdf"] == "scrypt"

    assert b2chks.verify(str(manifest_path))

    fail_success = b2chks.extract(
        str(manifest_path),
        output_dir=str(extract_dir),
        decrypt_key="WrongPassword",
    )
    assert not fail_success

    ok = b2chks.extract(
        str(manifest_path),
        output_dir=str(extract_dir),
        decrypt_key=passphrase,
    )
    assert ok

    extracted_project = extract_dir / "my_project"
    assert extracted_project.is_dir()
    assert (extracted_project / "file1.txt").read_text(encoding="utf-8") == "Hello World!"
    assert (extracted_project / "subfolder" / "data.bin").read_bytes() == (b"\x00\x01\x02\x03\xff" * 4000)


def test_pack_with_keygen_flag(tmp_path):
    src_file = tmp_path / "doc.txt"
    src_file.write_text("Document with auto keygen", encoding="utf-8")
    dist_dir = tmp_path / "auto_dist"

    manifest_path = b2chks.pack(
        source=str(src_file),
        chunk_size_str="10k",
        output_dir=str(dist_dir),
        generate_key=True,
        author="auto_author",
    )

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["security"]["developer_id"] == "auto_author"
    assert len(manifest["security"]["signature"]) > 0
    assert (dist_dir / "private.pem").exists()
    assert (dist_dir / "public.pem").exists()
    assert b2chks.verify(str(manifest_path))


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

    chunk0 = dist_dir / "chunk_000.bin"
    chunk0.write_bytes(b"CORRUPTED_BYTES" + chunk0.read_bytes())
    assert not b2chks.verify(str(manifest_path))

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

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["package_info"]["name"] = "tampered_name.dat"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    assert not b2chks.verify(str(manifest_path), public_key_path=pub)


def test_core_py_and_core_pykeygen_cli(tmp_path):
    res = subprocess.run(
        [sys.executable, "core.pykeygen", "--author", "arcxan", "--out-dir", str(tmp_path / "keys")],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert (tmp_path / "keys" / "private.pem").exists()
    assert (tmp_path / "keys" / "public.pem").exists()

    src_folder = tmp_path / "my_game_folder"
    src_folder.mkdir()
    (src_folder / "game.bin").write_bytes(b"\xaa\xbb" * 1000)

    res = subprocess.run(
        [
            sys.executable,
            "core.py",
            "pack",
            str(src_folder),
            "--chunk-size",
            "500m",
            "--encrypt-key",
            "MySecretPassphrase123",
            "--output-dir",
            str(tmp_path / "dist_core"),
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    manifest = tmp_path / "dist_core" / "manifest.json"
    assert manifest.exists()

    res = subprocess.run(
        [
            sys.executable,
            "core.py",
            "extract",
            str(manifest),
            "--output-dir",
            str(tmp_path / "ext_core"),
            "--decrypt-key",
            "MySecretPassphrase123",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert (tmp_path / "ext_core" / "my_game_folder" / "game.bin").read_bytes() == (b"\xaa\xbb" * 1000)


def test_installer_reinstall_and_uninstall():
    install.install()
    assert install.is_installed()

    install.install()
    assert install.is_installed()

    ok = install.uninstall()
    assert ok
    assert not install.is_installed()

    ok2 = install.uninstall()
    assert not ok2

    install.install()
    assert install.is_installed()
