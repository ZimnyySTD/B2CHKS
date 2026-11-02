#!/usr/bin/env python3
"""
B2CHKS: High-performance file packaging, chunking, compression, and secure distribution protocol.
"""

import argparse
import getpass
import gzip
import io
import json
import os
import shutil
import sys
import tarfile
from hashlib import sha256
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROTOCOL_VERSION = "b2chks"
PBKDF2_ITERATIONS = 600_000
NONCE_SIZE = 12
TAG_SIZE = 16


def parse_size(size_str: str) -> int:
    """Parse human readable size string like 100k, 500m, 2g, 1024 to integer bytes."""
    if not size_str:
        raise ValueError("Chunk size cannot be empty")
    size_str = size_str.strip().lower()
    units = {
        'b': 1,
        'k': 1024,
        'kb': 1024,
        'm': 1024 * 1024,
        'mb': 1024 * 1024,
        'g': 1024 * 1024 * 1024,
        'gb': 1024 * 1024 * 1024,
        't': 1024 * 1024 * 1024 * 1024,
        'tb': 1024 * 1024 * 1024 * 1024,
    }

    unit = ""
    num_part = size_str
    for u in sorted(units.keys(), key=len, reverse=True):
        if size_str.endswith(u):
            unit = u
            num_part = size_str[:-len(u)]
            break

    try:
        val = float(num_part)
        multiplier = units.get(unit, 1)
        bytes_val = int(val * multiplier)
        if bytes_val <= 0:
            raise ValueError("Chunk size must be positive")
        return bytes_val
    except ValueError as e:
        raise ValueError(f"Invalid size string: '{size_str}'") from e


def generate_keypair(author: str, out_dir: str = ".") -> Tuple[str, str]:
    """Generate Ed25519 keypair and save to private.pem and public.pem."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    priv_file = out_path / "private.pem"
    pub_file = out_path / "public.pem"

    with open(priv_file, "wb") as f:
        f.write(priv_bytes)
    with open(pub_file, "wb") as f:
        f.write(pub_bytes)

    return str(priv_file), str(pub_file)


def derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 256-bit key from passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def get_canonical_json_bytes(manifest_dict: Dict[str, Any]) -> bytes:
    """Produce deterministic canonical JSON bytes excluding the signature field."""
    # Deep copy or filter out security.signature
    clean = json.loads(json.dumps(manifest_dict))
    if "security" in clean and "signature" in clean["security"]:
        del clean["security"]["signature"]
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compress_source_to_stream(source_path: Path, temp_file_path: Path) -> Tuple[int, str]:
    """
    Compress file or directory into temp_file_path using gzip.
    Returns (uncompressed_total_size, source_type).
    """
    if source_path.is_file():
        source_type = "file"
        total_size = source_path.stat().st_size
        with open(source_path, "rb") as f_in, gzip.open(temp_file_path, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out)
        return total_size, source_type
    elif source_path.is_dir():
        source_type = "directory"
        total_size = 0
        for root, _, files in os.walk(source_path):
            for file in files:
                fp = Path(root) / file
                if not fp.is_symlink():
                    total_size += fp.stat().st_size

        with tarfile.open(temp_file_path, "w:gz", compresslevel=6) as tar:
            tar.add(str(source_path), arcname=source_path.name)
        return total_size, source_type
    else:
        raise FileNotFoundError(f"Source path {source_path} does not exist")


def pack(
    source: str,
    chunk_size_str: str,
    output_dir: str = "./dist",
    encrypt_key: Optional[str] = None,
    private_key_path: Optional[str] = None,
    author: Optional[str] = None,
) -> Path:
    """Pack a file or directory into compressed, optionally encrypted chunks with manifest."""
    source_path = Path(source).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Source {source} does not exist.")

    chunk_size = parse_size(chunk_size_str)
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Temporary compressed archive path
    temp_archive = out_dir / f".tmp_{source_path.name}.archive"

    print(f"[*] Compressing source '{source_path.name}'...")
    total_uncompressed_size, source_type = compress_source_to_stream(source_path, temp_archive)
    compressed_size = temp_archive.stat().st_size
    print(f"[*] Compressed {total_uncompressed_size} bytes -> {compressed_size} bytes.")

    # Encryption setup
    is_encrypted = bool(encrypt_key)
    salt_hex = None
    aesgcm = None
    if is_encrypted:
        salt = os.urandom(16)
        salt_hex = salt.hex()
        aes_key = derive_aes_key(encrypt_key, salt)
        aesgcm = AESGCM(aes_key)
        # In encrypted chunking: each chunk file will store: [12-byte nonce] + [ciphertext + 16-byte tag]
        # Raw data read per chunk should account for overhead if we want chunk files to not exceed chunk_size,
        # but standard convention is payload chunk size = chunk_size, resulting in file size = chunk_size + 28 bytes.
        # Alternatively, max chunk file size = chunk_size.
        # Let's adjust read_size so encrypted chunk file is at most chunk_size (if chunk_size > 28).
        if chunk_size > (NONCE_SIZE + TAG_SIZE):
            read_chunk_size = chunk_size - (NONCE_SIZE + TAG_SIZE)
        else:
            read_chunk_size = chunk_size
    else:
        read_chunk_size = chunk_size

    # Signing setup
    priv_key_obj = None
    pub_key_hex = None
    dev_id = author or ""

    # Look for private key
    cand_priv_key = private_key_path or "private.pem"
    if cand_priv_key and Path(cand_priv_key).exists():
        try:
            with open(cand_priv_key, "rb") as f:
                priv_key_obj = serialization.load_pem_private_key(f.read(), password=None)
            if isinstance(priv_key_obj, ed25519.Ed25519PrivateKey):
                pub_key = priv_key_obj.public_key()
                pub_bytes = pub_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                pub_key_hex = pub_bytes.hex()
                if not dev_id:
                    dev_id = "author"
            else:
                priv_key_obj = None
        except Exception as e:
            print(f"[!] Warning: Failed to load private key from {cand_priv_key}: {e}")
            priv_key_obj = None

    chunks_meta = []
    chunk_index = 0

    print(f"[*] Splitting into chunks of target size {chunk_size} bytes...")
    with open(temp_archive, "rb") as src_f:
        while True:
            chunk_data = src_f.read(read_chunk_size)
            if not chunk_data:
                # If source is completely empty file, create one empty chunk
                if chunk_index == 0:
                    chunk_data = b""
                else:
                    break

            if is_encrypted:
                nonce = os.urandom(NONCE_SIZE)
                # Encrypt chunk data (returns ciphertext + tag)
                ciphertext_with_tag = aesgcm.encrypt(nonce, chunk_data, associated_data=chunk_index.to_bytes(4, "big"))
                file_bytes = nonce + ciphertext_with_tag
            else:
                file_bytes = chunk_data

            chunk_filename = f"chunk_{chunk_index:03d}.bin"
            chunk_path = out_dir / chunk_filename
            with open(chunk_path, "wb") as cf:
                cf.write(file_bytes)

            chunk_hash = sha256(file_bytes).hexdigest()
            chunks_meta.append({
                "index": chunk_index,
                "filename": chunk_filename,
                "size": len(file_bytes),
                "sha256": chunk_hash,
            })

            chunk_index += 1
            if not chunk_data:
                break

    # Clean up temp archive
    if temp_archive.exists():
        temp_archive.unlink()

    package_info: Dict[str, Any] = {
        "name": source_path.name,
        "source_type": source_type,
        "total_size_bytes": total_uncompressed_size,
        "chunk_size_bytes": chunk_size,
        "total_chunks": len(chunks_meta),
        "encrypted": is_encrypted,
    }

    manifest: Dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "package_info": package_info,
        "security": {
            "developer_id": dev_id,
            "public_key": pub_key_hex or "",
            "signature": "",
        },
        "chunks": chunks_meta,
    }

    if is_encrypted:
        manifest["encryption"] = {
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": salt_hex,
        }

    # Sign manifest if private key available
    if priv_key_obj:
        canonical_bytes = get_canonical_json_bytes(manifest)
        signature = priv_key_obj.sign(canonical_bytes)
        manifest["security"]["signature"] = signature.hex()
        print(f"[*] Manifest cryptographically signed with Ed25519 key (developer_id: {dev_id}).")
    else:
        print("[*] No private key provided/found; manifest generated without signature.")

    manifest_file = out_dir / "manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"[+] Packaging complete! Manifest: {manifest_file} ({len(chunks_meta)} chunks created)")
    return manifest_file


def verify(
    manifest_path: str,
    chunks_dir: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> bool:
    """Verify chunk inventory, SHA-256 hashes, and Ed25519 author signature."""
    mpath = Path(manifest_path).resolve()
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    with open(mpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    print(f"[*] Verifying package '{manifest.get('package_info', {}).get('name', 'unknown')}'...")
    print(f"[*] Manifest protocol: {manifest.get('protocol')}")

    # 1. Verify Ed25519 signature if present
    sec = manifest.get("security", {})
    signature_hex = sec.get("signature")
    pub_key_hex = sec.get("public_key")

    pub_key_obj = None
    if public_key_path and Path(public_key_path).exists():
        try:
            with open(public_key_path, "rb") as f:
                pem_data = f.read()
                pub_key_obj = serialization.load_pem_public_key(pem_data)
        except Exception as e:
            print(f"[-] Failed to load public key from {public_key_path}: {e}")
            return False
    elif pub_key_hex:
        try:
            pub_bytes = bytes.fromhex(pub_key_hex)
            pub_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as e:
            print(f"[-] Invalid public key hex in manifest: {e}")
            return False

    if signature_hex and pub_key_obj:
        try:
            sig_bytes = bytes.fromhex(signature_hex)
            canonical_bytes = get_canonical_json_bytes(manifest)
            pub_key_obj.verify(sig_bytes, canonical_bytes)
            print(f"[+] Authorship signature VALID (Developer ID: '{sec.get('developer_id')}').")
        except Exception as e:
            print(f"[-] Cryptographic signature verification FAILED: {e}")
            return False
    elif signature_hex and not pub_key_obj:
        print("[!] Warning: Manifest contains signature but no public key could be found to verify.")
    else:
        print("[*] Manifest is unsigned.")

    # 2. Verify chunks inventory and integrity
    chunks = manifest.get("chunks", [])
    if not chunks:
        print("[-] Error: Manifest contains no chunk definitions.")
        return False

    # Scan directory by hash or filename
    # First map all available files in c_dir by sha256
    file_hashes: Dict[str, Path] = {}
    for p in c_dir.iterdir():
        if p.is_file() and p != mpath:
            with open(p, "rb") as f:
                h = sha256(f.read()).hexdigest()
                file_hashes[h] = p

    all_valid = True
    missing_chunks = []
    corrupted_chunks = []

    for chunk_info in sorted(chunks, key=lambda x: x["index"]):
        idx = chunk_info["index"]
        expected_hash = chunk_info["sha256"]
        expected_name = chunk_info.get("filename", f"chunk_{idx:03d}.bin")
        expected_size = chunk_info.get("size")

        # Check by expected filename first
        cf_path = c_dir / expected_name
        if cf_path.exists():
            with open(cf_path, "rb") as cf:
                actual_hash = sha256(cf.read()).hexdigest()
            if actual_hash == expected_hash:
                continue
            else:
                corrupted_chunks.append((idx, expected_name, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"))
                all_valid = False
                continue

        # If not at expected filename, check if file exists with matching hash
        if expected_hash in file_hashes:
            continue

        missing_chunks.append((idx, expected_name, expected_hash))
        all_valid = False

    if missing_chunks:
        print(f"[-] Missing {len(missing_chunks)} chunk(s):")
        for idx, fname, h in missing_chunks:
            print(f"    - Index {idx} ({fname}): SHA-256 {h}")

    if corrupted_chunks:
        print(f"[-] Corrupted {len(corrupted_chunks)} chunk(s):")
        for idx, fname, reason in corrupted_chunks:
            print(f"    - Index {idx} ({fname}): {reason}")

    if all_valid:
        print(f"[+] All {len(chunks)} chunks verified successfully! Integrity check PASSED.")
        return True
    else:
        print("[-] Chunk verification FAILED.")
        return False


def extract(
    manifest_path: str,
    chunks_dir: Optional[str] = None,
    output_dir: str = "./extracted",
    decrypt_key: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> bool:
    """Verify chunks, decrypt (if needed), reassemble, and decompress in one go."""
    mpath = Path(manifest_path).resolve()
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    with open(mpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    # Run verification first
    print("[*] Running pre-flight verification...")
    if not verify(str(mpath), str(c_dir), public_key_path):
        print("[-] Pre-flight verification failed. Aborting extraction.")
        return False

    package_info = manifest.get("package_info", {})
    is_encrypted = package_info.get("encrypted", False)
    source_type = package_info.get("source_type", "file")
    target_name = package_info.get("name", "extracted_output")

    aesgcm = None
    if is_encrypted:
        enc_info = manifest.get("encryption", {})
        salt_hex = enc_info.get("salt")
        if not salt_hex:
            print("[-] Error: Package is encrypted but salt is missing from manifest.")
            return False
        salt = bytes.fromhex(salt_hex)

        passphrase = decrypt_key
        if not passphrase:
            try:
                passphrase = getpass.getpass("This package is cryptographically locked. Enter decryption key: ")
            except (KeyboardInterrupt, EOFError):
                print("\n[-] Decryption aborted by user.")
                return False

        if not passphrase:
            print("[-] Decryption key is required.")
            return False

        aes_key = derive_aes_key(passphrase, salt)
        aesgcm = AESGCM(aes_key)

    # Locate chunks
    chunks = sorted(manifest.get("chunks", []), key=lambda x: x["index"])

    # Map files by sha256 in c_dir
    hash_to_path: Dict[str, Path] = {}
    for p in c_dir.iterdir():
        if p.is_file() and p != mpath:
            with open(p, "rb") as f:
                h = sha256(f.read()).hexdigest()
                hash_to_path[h] = p

    out_base = Path(output_dir).resolve()
    out_base.mkdir(parents=True, exist_ok=True)

    # Reassemble compressed stream into a temporary file
    temp_reassembled = out_base / f".tmp_{target_name}.archive"
    print(f"[*] Reassembling {len(chunks)} chunks...")

    try:
        with open(temp_reassembled, "wb") as out_f:
            for chunk_info in chunks:
                idx = chunk_info["index"]
                expected_hash = chunk_info["sha256"]
                expected_name = chunk_info.get("filename")

                cf_path = c_dir / expected_name if expected_name else None
                if not (cf_path and cf_path.exists() and sha256(cf_path.read_bytes()).hexdigest() == expected_hash):
                    cf_path = hash_to_path.get(expected_hash)

                if not cf_path or not cf_path.exists():
                    print(f"[-] Could not find chunk file for index {idx} (hash {expected_hash})")
                    return False

                with open(cf_path, "rb") as cf:
                    raw_chunk = cf.read()

                if is_encrypted:
                    if len(raw_chunk) < (NONCE_SIZE + TAG_SIZE):
                        print(f"[-] Corrupt encrypted chunk {idx}: file too small")
                        return False
                    nonce = raw_chunk[:NONCE_SIZE]
                    ciphertext_with_tag = raw_chunk[NONCE_SIZE:]
                    try:
                        decrypted_data = aesgcm.decrypt(
                            nonce,
                            ciphertext_with_tag,
                            associated_data=idx.to_bytes(4, "big"),
                        )
                    except Exception:
                        print("[-] Cryptographic authentication layer rejected decryption key or corrupted data.")
                        return False
                    out_f.write(decrypted_data)
                else:
                    out_f.write(raw_chunk)

        # Decompress reconstructed archive
        print(f"[*] Decompressing and reconstructing '{target_name}' (type: {source_type})...")
        destination_path = out_base / target_name

        if source_type == "file":
            with gzip.open(temp_reassembled, "rb") as gz_in, open(destination_path, "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)
        elif source_type == "directory":
            with tarfile.open(temp_reassembled, "r:gz") as tar:
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(path=out_base, filter='data')
                else:
                    tar.extractall(path=out_base)
        else:
            print(f"[-] Unknown source_type '{source_type}'.")
            return False

        print(f"[+] Reassembly and extraction complete -> {destination_path}")
        return True

    finally:
        if temp_reassembled.exists():
            temp_reassembled.unlink()


def main():
    parser = argparse.ArgumentParser(
        prog="b2chks",
        description="B2CHKS: High-performance file packaging, chunking, compression, and distribution tool.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Keygen subcommand
    parser_keygen = subparsers.add_parser("keygen", help="Generate Ed25519 signing keypair")
    parser_keygen.add_argument("--author", "-a", type=str, default="author", help="Author/developer identifier")
    parser_keygen.add_argument("--out-dir", "-o", type=str, default=".", help="Output directory for keys")

    # Pack subcommand (and aliases)
    for name in ["pack", "package", "compress"]:
        parser_pack = subparsers.add_parser(name, help="Compress, chunk, encrypt and sign a file or directory")
        parser_pack.add_argument("source", type=str, help="Path to file or directory to pack")
        parser_pack.add_argument(
            "--chunk-size", "-c",
            type=str,
            required=True,
            help="Size of each chunk (e.g. 100m, 500m, 1g, 500k). Required.",
        )
        parser_pack.add_argument("--encrypt-key", "-e", type=str, default=None, help="Passphrase to encrypt chunks with AES-256-GCM")
        parser_pack.add_argument("--private-key", "-k", type=str, default=None, help="Path to Ed25519 private.pem to sign manifest")
        parser_pack.add_argument("--author", "-a", type=str, default=None, help="Author/Developer ID for manifest")
        parser_pack.add_argument("--output-dir", "-o", type=str, default="./dist", help="Output directory for chunks and manifest")

    # Verify subcommand
    parser_verify = subparsers.add_parser("verify", help="Verify chunk integrity and author signature")
    parser_verify.add_argument("manifest", type=str, help="Path to manifest.json")
    parser_verify.add_argument("--chunks-dir", "-d", type=str, default=None, help="Directory containing chunk files (defaults to manifest dir)")
    parser_verify.add_argument("--public-key", "-k", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")

    # Extract subcommand
    parser_extract = subparsers.add_parser("extract", help="Verify, decrypt, assemble, and decompress package")
    parser_extract.add_argument("manifest", type=str, help="Path to manifest.json")
    parser_extract.add_argument("--chunks-dir", "-d", type=str, default=None, help="Directory containing chunk files (defaults to manifest dir)")
    parser_extract.add_argument("--output-dir", "-o", type=str, default="./extracted", help="Destination directory for extracted files")
    parser_extract.add_argument("--decrypt-key", "-e", type=str, default=None, help="Decryption key passphrase (prompts if omitted and encrypted)")
    parser_extract.add_argument("--public-key", "-k", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "keygen":
            priv, pub = generate_keypair(args.author, args.out_dir)
            print(f"[+] Generated Ed25519 keypair for author '{args.author}':")
            print(f"    Private key: {priv}")
            print(f"    Public key:  {pub}")

        elif args.command in ["pack", "package", "compress"]:
            pack(
                source=args.source,
                chunk_size_str=args.chunk_size,
                output_dir=args.output_dir,
                encrypt_key=args.encrypt_key,
                private_key_path=args.private_key,
                author=args.author,
            )

        elif args.command == "verify":
            ok = verify(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                public_key_path=args.public_key,
            )
            if not ok:
                sys.exit(1)

        elif args.command == "extract":
            ok = extract(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                output_dir=args.output_dir,
                decrypt_key=args.decrypt_key,
                public_key_path=args.public_key,
            )
            if not ok:
                sys.exit(1)

    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
