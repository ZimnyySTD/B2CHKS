"""Single-pass verification and streaming extraction engine."""
import concurrent.futures
import getpass
import hashlib
import os
import sys
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Callable, Dict, Any, Tuple, List

from b2chks.chunking import ByteBudget
from b2chks.compression import decompress_stream, decompress_reader, PrefetchChunkReader
from b2chks.encryption import (
    NONCE_SIZE,
    TAG_SIZE,
    derive_aes_key,
    get_aes_gcm_cipher,
)
from b2chks.exceptions import (
    IntegrityError,
    AuthenticationError,
    DecryptionError,
    CompressionError,
    CancelledError,
)
from b2chks.hashing import hash_file
from b2chks.manifest import load_manifest, get_canonical_json_bytes
from b2chks.signing import verify_signature

STREAM_READ_BUFFER = 1024 * 1024  # 1MB buffer for reading/hashing
MAX_EXTRACT_BUDGET = 64 * 1024 * 1024  # 64MB memory budget for extraction


def resolve_manifest_path(input_path: Optional[str] = None) -> Path:
    """Resolve manifest file path, handling directories, None, or explicit filenames."""
    if not input_path or input_path == ".":
        cand = Path("manifest.json").resolve()
        if cand.exists():
            return cand
        cand = Path("dist/manifest.json").resolve()
        if cand.exists():
            return cand
        return Path("manifest.json").resolve()

    p = Path(input_path).resolve()
    if p.is_dir():
        cand = p / "manifest.json"
        if cand.exists():
            return cand
        return cand
    return p


def _find_chunk_file(c_dir: Path, expected_name: str, expected_hash: str) -> Optional[Path]:
    """Look up chunk file by expected filename first, falling back to directory scan only if missing."""
    target = c_dir / expected_name
    if target.exists():
        return target

    # Fallback only when filename does not match
    for p in c_dir.iterdir():
        if p.is_file() and p.name != "manifest.json":
            if hash_file(p) == expected_hash:
                return p
    return None


def verify(
    manifest_path: Optional[str] = None,
    chunks_dir: Optional[str] = None,
    public_key_path: Optional[str] = None,
    trusted_public_key_path: Optional[str] = None,
    workers: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> bool:
    """Verify chunk inventory, streaming SHA-256 hashes, and Ed25519 author signature."""
    mpath = resolve_manifest_path(manifest_path)
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    manifest = load_manifest(mpath)
    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    # 1. Signature check
    sec = manifest.get("security", {})
    signature_hex = sec.get("signature")
    pub_key_hex = sec.get("public_key")
    pub_source = trusted_public_key_path or public_key_path or pub_key_hex
    if not pub_source:
        candidate = c_dir / "public.pem"
        pub_source = candidate if candidate.exists() else Path("public.pem")

    if signature_hex:
        canonical_bytes = get_canonical_json_bytes(manifest)
        if not verify_signature(canonical_bytes, signature_hex, pub_source):
            print("[-] Cryptographic signature verification FAILED.")
            return False
        print(f"[+] Authorship signature VALID (Developer ID: '{sec.get('developer_id')}').")
    elif trusted_public_key_path:
        print("[-] A trusted public key was supplied but the manifest is unsigned.")
        return False
    else:
        print("[*] Manifest is unsigned.")

    chunks = manifest.get("chunks", [])
    max_workers = workers if workers and workers > 0 else min(os.cpu_count() or 4, 8)

    def _verify_single_chunk(chunk_info: Dict[str, Any]) -> Tuple[int, str, bool, Optional[str]]:
        idx = chunk_info["index"]
        expected_hash = chunk_info["sha256"]
        expected_name = chunk_info.get("filename", f"chunk_{idx:03d}.bin")
        target_path = c_dir / expected_name

        if not target_path.exists():
            # Fallback discovery
            found = _find_chunk_file(c_dir, expected_name, expected_hash)
            if not found:
                return idx, expected_name, False, "Missing chunk file"
            target_path = found

        actual_hash = hash_file(target_path)
        if actual_hash == expected_hash:
            return idx, expected_name, True, None
        return idx, expected_name, False, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"

    all_valid = True
    missing_chunks = []
    corrupted_chunks = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_verify_single_chunk, c): c for c in chunks}
        for i, fut in enumerate(concurrent.futures.as_completed(futures)):
            if cancel_token and cancel_token():
                raise CancelledError("Verification cancelled by user")

            idx, expected_name, ok, reason = fut.result()
            if progress_callback:
                progress_callback(i + 1, len(chunks), "verifying")

            if not ok:
                all_valid = False
                if "Missing" in (reason or ""):
                    missing_chunks.append((idx, expected_name))
                else:
                    corrupted_chunks.append((idx, expected_name, reason))

    if missing_chunks:
        print(f"[-] Missing {len(missing_chunks)} chunk(s):")
        for idx, fname in missing_chunks:
            print(f"    - Index {idx} ({fname})")

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


def _read_and_process_chunk(
    idx: int,
    cpath: Path,
    expected_hash: str,
    is_encrypted: bool,
    cipher: Optional[Any],
    byte_budget: ByteBudget,
) -> Tuple[int, bytes]:
    """
    Single-pass worker: Reads chunk file, verifies SHA-256 incrementally,
    decrypts payload if encrypted, and returns decrypted plaintext.
    """
    try:
        # Stream read and hash simultaneously in single pass
        h = hashlib.sha256()
        raw_parts = []
        with open(cpath, "rb", buffering=STREAM_READ_BUFFER) as f:
            while True:
                buf = f.read(STREAM_READ_BUFFER)
                if not buf:
                    break
                h.update(buf)
                raw_parts.append(buf)

        actual_hash = h.hexdigest()
        if actual_hash != expected_hash:
            raise IntegrityError(f"Hash mismatch on chunk {idx} ({cpath.name}): expected {expected_hash}, got {actual_hash}")

        raw_chunk = b"".join(raw_parts) if len(raw_parts) > 1 else (raw_parts[0] if raw_parts else b"")

        if is_encrypted and cipher:
            if len(raw_chunk) < (NONCE_SIZE + TAG_SIZE):
                raise DecryptionError(f"Corrupt encrypted chunk {idx}: file too small")
            nonce = raw_chunk[:NONCE_SIZE]
            ciphertext_with_tag = raw_chunk[NONCE_SIZE:]
            try:
                decrypted_data = cipher.decrypt(
                    nonce,
                    ciphertext_with_tag,
                    associated_data=idx.to_bytes(4, "big"),
                )
            except Exception as e:
                raise DecryptionError(f"Cryptographic authentication tag mismatch on chunk {idx}") from e
            return idx, decrypted_data

        return idx, raw_chunk

    finally:
        pass


def extract(
    manifest_path: Optional[str] = None,
    chunks_dir: Optional[str] = None,
    output_dir: Optional[str] = None,
    decrypt_key: Optional[str] = None,
    public_key_path: Optional[str] = None,
    trusted_public_key_path: Optional[str] = None,
    workers: Optional[int] = None,
    memory_budget_bytes: Optional[int] = None,
    max_output_size: Optional[int] = None,
    max_files: Optional[int] = None,
    max_file_size: Optional[int] = None,
    max_compression_ratio: Optional[float] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> bool:
    """
    Verify and extract package in a SINGLE PASS:
    Reads each chunk file once, verifies SHA-256 and decrypts in the same stream,
    writing directly to decompressor without redundant disk passes.
    """
    mpath = resolve_manifest_path(manifest_path)
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    manifest = load_manifest(mpath)
    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    # 1. Author signature check
    sec = manifest.get("security", {})
    signature_hex = sec.get("signature")
    pub_key_hex = sec.get("public_key")
    pub_source = trusted_public_key_path or public_key_path or pub_key_hex
    if not pub_source:
        candidate = c_dir / "public.pem"
        pub_source = candidate if candidate.exists() else Path("public.pem")

    if signature_hex:
        canonical_bytes = get_canonical_json_bytes(manifest)
        if not verify_signature(canonical_bytes, signature_hex, pub_source):
            print("[-] Cryptographic signature verification FAILED.")
            return False
        print(f"[+] Authorship signature VALID (Developer ID: '{sec.get('developer_id')}').")
    elif trusted_public_key_path:
        print("[-] A trusted public key was supplied but the manifest is unsigned.")
        return False

    package_info = manifest.get("package_info", {})
    is_encrypted = package_info.get("encrypted", False)
    source_type = package_info.get("source_type", "file")
    target_name = package_info.get("name", "extracted_output")
    compression_algo = package_info.get("compression", "gzip")
    if Path(target_name).name != target_name or Path(target_name).is_absolute():
        print("[-] Unsafe output name in manifest.")
        return False
    if max_output_size is not None and package_info.get("total_size_bytes", 0) > max_output_size:
        print("[-] Package exceeds the configured output-size limit.")
        return False
    if max_files is not None and source_type == "file" and max_files < 1:
        print("[-] Package exceeds the configured file-count limit.")
        return False
    if max_file_size is not None and source_type == "file" and package_info.get("total_size_bytes", 0) > max_file_size:
        print("[-] Package exceeds the configured file-size limit.")
        return False

    cipher = None
    if is_encrypted:
        enc_info = manifest.get("encryption", {})
        salt_hex = enc_info.get("salt")
        if not salt_hex:
            print("[-] Error: Package is encrypted but salt is missing from manifest.")
            return False
        salt = bytes.fromhex(salt_hex)

        passphrase = decrypt_key
        if not passphrase:
            prompt_msg = "This package is cryptographically locked. Enter decryption key: "
            try:
                if sys.stdin.isatty():
                    passphrase = getpass.getpass(prompt_msg)
                else:
                    print(prompt_msg, end="", flush=True)
                    passphrase = sys.stdin.readline().strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[-] Decryption aborted by user.")
                return False

        if not passphrase:
            print("[-] Decryption key is required.")
            return False

        kdf_name = enc_info.get("kdf", "scrypt")
        aes_key = derive_aes_key(passphrase, salt, kdf_name, enc_info)
        cipher = get_aes_gcm_cipher(aes_key)

    chunks = sorted(manifest.get("chunks", []), key=lambda x: x["index"])
    out_base = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_base.mkdir(parents=True, exist_ok=True)

    stage_dir = Path(tempfile.mkdtemp(prefix=".b2chks-", dir=out_base))
    reader = None
    try:
        # Direct filename lookup without rescanning the directory
        chunk_targets: List[Tuple[int, Path, str]] = []
        for chunk_info in chunks:
            idx = chunk_info["index"]
            expected_hash = chunk_info["sha256"]
            expected_name = chunk_info.get("filename", f"chunk_{idx:03d}.bin")
            cf_path = _find_chunk_file(c_dir, expected_name, expected_hash)
            if not cf_path:
                print(f"[-] Could not find chunk file for index {idx} ({expected_name})")
                return False
            expected_size = chunk_info.get("size")
            if expected_size is not None and cf_path.stat().st_size != expected_size:
                print(f"[-] Chunk size mismatch for index {idx}")
                return False
            if memory_budget_bytes is not None and expected_size is not None and expected_size > memory_budget_bytes:
                print(f"[-] Chunk {idx} exceeds the configured memory limit.")
                return False
            chunk_targets.append((idx, cf_path, expected_hash))

        if max_compression_ratio is not None:
            compressed_size = sum(path.stat().st_size for _, path, _ in chunk_targets)
            if compressed_size and package_info.get("total_size_bytes", 0) / compressed_size > max_compression_ratio:
                print("[-] Package exceeds the configured compression-ratio limit.")
                return False

        def read_verified(item):
            idx, cpath, expected_hash = item
            if cancel_token and cancel_token():
                raise CancelledError("Extraction cancelled by user")
            raw = cpath.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_hash:
                raise IntegrityError(f"Hash mismatch on chunk {idx} ({cpath.name})")
            if is_encrypted and cipher:
                if len(raw) < NONCE_SIZE + TAG_SIZE:
                    raise DecryptionError(f"Corrupt encrypted chunk {idx}: file too small")
                try:
                    return cipher.decrypt(
                        raw[:NONCE_SIZE], raw[NONCE_SIZE:], associated_data=idx.to_bytes(4, "big")
                    )
                except Exception as exc:
                    raise DecryptionError(
                        f"Cryptographic authentication tag mismatch on chunk {idx}"
                    ) from exc
            return raw

        reader = PrefetchChunkReader(
            chunk_targets,
            lambda item: read_verified(item),
            workers=workers if workers and workers > 0 else min(os.cpu_count() or 2, 4),
        )
        try:
            destination_path = decompress_reader(
                reader,
                stage_dir,
                target_name,
                source_type,
                algorithm=compression_algo,
                max_files=max_files,
                max_file_size=max_file_size,
            )
        except (IntegrityError, DecryptionError, AuthenticationError, CompressionError) as exc:
            print(f"[-] Extraction error: {exc}")
            return False
        final_path = out_base / target_name
        if final_path.exists():
            if final_path.is_dir():
                shutil.rmtree(final_path)
            else:
                final_path.unlink()
        stage_target = stage_dir / target_name
        stage_target.replace(final_path)
        if progress_callback:
            progress_callback(len(chunk_targets), len(chunk_targets), "extracting")
        print(f"[+] Reassembly and extraction complete -> {final_path}")
        return True

    finally:
        if reader is not None:
            reader.close()
        shutil.rmtree(stage_dir, ignore_errors=True)
