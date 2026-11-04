"""Packing engine orchestrating compression, encryption, chunking, and signing."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List

from b2chks.chunking import parse_size, ByteBudget
from b2chks.compression import compress_stream
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

        # Hash with incremental update
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
    chunk_size_str: str,
    output_dir: Optional[str] = None,
    encrypt_key: Optional[str] = None,
    private_key_path: Optional[str] = None,
    author: Optional[str] = None,
    generate_key: bool = False,
    compression: str = "gzip",
    kdf: str = "scrypt",
    workers: Optional[int] = None,
    memory_budget_bytes: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> Path:
    """Pack a file or directory into compressed, optionally encrypted chunks with manifest."""
    source_path = Path(source).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Source {source} does not exist.")

    chunk_size = parse_size(chunk_size_str)
    out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

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

    temp_archive = out_dir / f".tmp_{source_path.name}.archive"

    # 1. Compress source
    total_uncompressed_size, source_type = compress_stream(
        source_path,
        temp_archive,
        algorithm=compression,
        compress_level=1,
        progress_callback=progress_callback,
    )

    # Determine actual compression algorithm used
    actual_compression = compression.lower()
    from b2chks.backends import HAVE_ZSTANDARD
    if actual_compression == "zstd" and not HAVE_ZSTANDARD:
        actual_compression = "gzip"

    if cancel_token and cancel_token():
        if temp_archive.exists():
            temp_archive.unlink()
        raise CancelledError("Packing cancelled by user")

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

        if chunk_size > (NONCE_SIZE + TAG_SIZE):
            read_chunk_size = chunk_size - (NONCE_SIZE + TAG_SIZE)
        else:
            read_chunk_size = chunk_size
    else:
        read_chunk_size = chunk_size

    # Conservative worker defaults (max 8 workers to prevent CPU/storage thrashing)
    max_workers = workers if workers and workers > 0 else min(os.cpu_count() or 4, 8)
    budget_limit = memory_budget_bytes or max(MAX_MEMORY_BUDGET, chunk_size * 2)
    byte_budget = ByteBudget(budget_limit)
    chunks_meta = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        chunk_index = 0
        in_flight = {}
        with open(temp_archive, "rb", buffering=4*1024*1024) as src_f:
            while True:
                if cancel_token and cancel_token():
                    if temp_archive.exists():
                        temp_archive.unlink()
                    raise CancelledError("Packing cancelled by user")

                # Acquire budget for the upcoming chunk before reading
                byte_budget.acquire(read_chunk_size)

                chunk_data = src_f.read(read_chunk_size)
                if not chunk_data:
                    byte_budget.release(read_chunk_size)
                    if chunk_index == 0:
                        chunk_data = b""
                        byte_budget.acquire(1)
                    else:
                        break

                fut = executor.submit(
                    _process_chunk_worker,
                    chunk_index,
                    chunk_data,
                    is_encrypted,
                    cipher,
                    out_dir,
                    byte_budget,
                )
                in_flight[fut] = chunk_index
                chunk_index += 1

                # Poll completed tasks
                done = [f for f in in_flight.keys() if f.done()]
                for d in done:
                    meta = d.result()
                    chunks_meta.append(meta)
                    del in_flight[d]
                    if progress_callback:
                        progress_callback(len(chunks_meta), chunk_index, "chunking")

                if not chunk_data:
                    break

            while in_flight:
                done, _ = concurrent.futures.wait(in_flight.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
                for d in done:
                    meta = d.result()
                    chunks_meta.append(meta)
                    del in_flight[d]
                    if progress_callback:
                        progress_callback(len(chunks_meta), chunk_index, "chunking")

    chunks_meta.sort(key=lambda x: x["index"])

    if temp_archive.exists():
        temp_archive.unlink()

    package_info: Dict[str, Any] = {
        "name": source_path.name,
        "source_type": source_type,
        "total_size_bytes": total_uncompressed_size,
        "chunk_size_bytes": chunk_size,
        "total_chunks": len(chunks_meta),
        "encrypted": is_encrypted,
        "compression": actual_compression,
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
