"""Packing engine orchestrating compression, encryption, chunking, and signing."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

from b2chks.chunking import parse_size, ByteBudget
from b2chks.compression import DEFAULT_ZSTD_LEVEL, compress_to_chunks
from b2chks.archive import create_zip
from b2chks.encryption import (
    NONCE_SIZE,
    TAG_SIZE,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    PBKDF2_ITERATIONS,
    derive_aes_key,
    get_aes_gcm_cipher,
)
from b2chks.exceptions import CancelledError
from b2chks.manifest import get_canonical_json_bytes, write_manifest
from b2chks.signing import generate_keypair, sign_data

PROTOCOL_VERSION = "b2chks"
MAX_MEMORY_BUDGET = 64 * 1024 * 1024  # 64MB default memory budget

def _process_chunk_worker(
    chunk_index: int,
    chunk_data: bytes,
    is_encrypted: bool,
    cipher: Optional[Any],
    out_dir: Path,
    byte_budget: Optional[ByteBudget] = None,
) -> Dict[str, Any]:
    """Process, encrypt, hash, and write a single chunk to disk reusing cipher instance."""
    try:
        if is_encrypted and cipher:
            nonce = os.urandom(NONCE_SIZE)
            ciphertext_with_tag = cipher.encrypt(
                nonce,
                chunk_data,
                associated_data=chunk_index.to_bytes(4, "big"),
            )
            file_bytes = nonce + ciphertext_with_tag
        else:
            file_bytes = chunk_data

        chunk_filename = f"chunk_{chunk_index:03d}.bin"
        chunk_path = out_dir / chunk_filename
        with open(chunk_path, "wb") as cf:
            cf.write(file_bytes)

        h = hashlib.sha256()
        h.update(file_bytes)
        chunk_hash = h.hexdigest()

        return {
            "index": chunk_index,
            "filename": chunk_filename,
            "size": len(file_bytes),
            "sha256": chunk_hash,
        }
    finally:
        if byte_budget:
            byte_budget.release(len(chunk_data))


def pack(
    source: str,
    chunk_size_str: Optional[str] = None,
    nochunks: bool = False,
    output_dir: Optional[str] = None,
    encrypt_key: Optional[str] = None,
    private_key_path: Optional[str] = None,
    author: Optional[str] = None,
    generate_key: bool = False,
    compression: str = "zstd",
    compression_level: int = DEFAULT_ZSTD_LEVEL,
    kdf: str = "scrypt",
    workers: Optional[int] = None,
    memory_budget_bytes: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> Path:
    """
    Pack a file or directory into compressed, optionally encrypted package with manifest.
    If nochunks=True, packs directly into a single chunk without splitting.
    """
    source_path = Path(source).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Source {source} does not exist.")

    out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not chunk_size_str and not nochunks:
        if encrypt_key or private_key_path or generate_key or author:
            raise ValueError("Encryption and signing require --chunk-size or --nochunks; plain ZIP archives do not contain a manifest.")
        return create_zip(source_path, out_dir, progress_callback, compression_level)

    priv_file = private_key_path
    if generate_key or (priv_file and not Path(priv_file).exists() and priv_file == "auto"):
        priv_str, _ = generate_keypair(author or "author", str(out_dir))
        priv_file = priv_str

    if not priv_file:
        cand = out_dir / "private.pem"
        if cand.exists():
            priv_file = str(cand)
        elif Path("private.pem").exists():
            priv_file = str(Path("private.pem").resolve())

    # Direct single-pass compression for nochunks
    is_encrypted = bool(encrypt_key)
    salt_hex = None
    cipher = None
    kdf_params = {}
    chosen_kdf = kdf

    if is_encrypted:
        salt = os.urandom(16)
        salt_hex = salt.hex()
        if chosen_kdf == "scrypt":
            kdf_params = {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
            aes_key = derive_aes_key(encrypt_key, salt, "scrypt", kdf_params)
        else:
            chosen_kdf = "PBKDF2-HMAC-SHA256"
            kdf_params = {"iterations": PBKDF2_ITERATIONS}
            aes_key = derive_aes_key(encrypt_key, salt, "PBKDF2-HMAC-SHA256", kdf_params)

        cipher = get_aes_gcm_cipher(aes_key)

    from b2chks.backends import HAVE_ZSTANDARD
    actual_compression = compression.lower()
    if actual_compression != "zstd":
        raise ValueError("Only Zstandard compression is supported for B2CHKS packages.")
    if not HAVE_ZSTANDARD:
        from b2chks.backends import require_zstandard
        require_zstandard()

    chunks_meta = []
    if chunk_size_str:
        chunk_size = parse_size(chunk_size_str)
    elif source_path.is_file():
        chunk_size = max(
            source_path.stat().st_size * 2 + NONCE_SIZE + TAG_SIZE + 1024 * 1024,
            MAX_MEMORY_BUDGET,
        )
    else:
        estimated_size = sum(
            fp.stat().st_size
            for root, _, files in os.walk(source_path)
            for fp in (Path(root) / name for name in files)
            if not fp.is_symlink()
        )
        chunk_size = max(estimated_size * 2 + NONCE_SIZE + TAG_SIZE + 1024 * 1024, MAX_MEMORY_BUDGET)
    effective_chunk_size = chunk_size
    payload_size = max(1, chunk_size - NONCE_SIZE - TAG_SIZE) if is_encrypted else chunk_size

    max_workers = workers if workers and workers > 0 else min(os.cpu_count() or 2, 4)
    pending = []
    next_index = 0

    def write_chunk(index: int, payload: bytes):
        if cancel_token and cancel_token():
            raise CancelledError("Packing cancelled by user")
        if is_encrypted and cipher:
            nonce = os.urandom(NONCE_SIZE)
            file_bytes = nonce + cipher.encrypt(
                nonce, payload, associated_data=index.to_bytes(4, "big")
            )
        else:
            file_bytes = payload
        filename = f"chunk_{index:03d}.bin"
        path = out_dir / filename
        with open(path, "wb", buffering=1024 * 1024) as chunk_file:
            chunk_file.write(file_bytes)
        return {
            "index": index,
            "filename": filename,
            "size": len(file_bytes),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    def emit_chunk(payload: bytes):
        nonlocal next_index
        if cancel_token and cancel_token():
            raise CancelledError("Packing cancelled by user")
        pending.append(executor.submit(write_chunk, next_index, payload))
        next_index += 1
        if len(pending) >= max_workers * 2:
            chunks_meta.append(pending.pop(0).result())
        if progress_callback:
            progress_callback(len(chunks_meta), 0, "chunking")

    try:
        total_uncompressed_size, source_type = compress_to_chunks(
            source_path,
            out_dir,
            payload_size,
            actual_compression,
            emit_chunk,
            progress_callback=progress_callback,
            compression_level=compression_level,
        )
        if not pending and not chunks_meta:
            emit_chunk(b"")
        while pending:
            chunks_meta.append(pending.pop(0).result())
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    chunks_meta.sort(key=lambda item: item["index"])

    package_info: Dict[str, Any] = {
        "name": source_path.name,
        "source_type": source_type,
        "total_size_bytes": total_uncompressed_size,
        "chunk_size_bytes": effective_chunk_size,
        "total_chunks": len(chunks_meta),
        "encrypted": is_encrypted,
        "compression": actual_compression,
        "nochunks": nochunks,
    }

    manifest: Dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "package_info": package_info,
        "security": {
            "developer_id": author or "",
            "public_key": "",
            "signature": "",
        },
        "chunks": chunks_meta,
    }

    if is_encrypted:
        manifest["encryption"] = {
            "algorithm": "AES-256-GCM",
            "kdf": chosen_kdf,
            "salt": salt_hex,
            **kdf_params,
        }

    # 3. Cryptographic author signature
    if priv_file and Path(priv_file).exists():
        signed = sign_data(b"", Path(priv_file))
        if signed:
            manifest["security"]["public_key"] = signed[1]
            if not manifest["security"]["developer_id"]:
                manifest["security"]["developer_id"] = author or "author"
            canonical_bytes = get_canonical_json_bytes(manifest)
            actual_signed = sign_data(canonical_bytes, Path(priv_file))
            if actual_signed:
                manifest["security"]["signature"] = actual_signed[0]

    manifest_file = out_dir / "manifest.json"
    write_manifest(manifest, manifest_file)
    return manifest_file
