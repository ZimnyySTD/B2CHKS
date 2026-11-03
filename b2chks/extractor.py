"""Verification and extraction engine."""
import concurrent.futures
import getpass
import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import Optional, Callable, Dict, Any, Tuple, List

from b2chks.compression import decompress_stream
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
    CancelledError,
)
from b2chks.manifest import load_manifest, get_canonical_json_bytes
from b2chks.signing import verify_signature

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


def verify(
    manifest_path: Optional[str] = None,
    chunks_dir: Optional[str] = None,
    public_key_path: Optional[str] = None,
    workers: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> bool:
    """Verify chunk inventory, SHA-256 hashes, and Ed25519 author signature."""
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
    pub_source = public_key_path or pub_key_hex or (c_dir / "public.pem") or Path("public.pem")

    if signature_hex:
        canonical_bytes = get_canonical_json_bytes(manifest)
        if not verify_signature(canonical_bytes, signature_hex, pub_source):
            print("[-] Cryptographic signature verification FAILED.")
            return False
        print(f"[+] Authorship signature VALID (Developer ID: '{sec.get('developer_id')}').")
    else:
        print("[*] Manifest is unsigned.")

    chunks = manifest.get("chunks", [])
    max_workers = workers if workers and workers > 0 else min(32, (os.cpu_count() or 4) * 2)

    def _hash_file(p: Path) -> Tuple[Path, str]:
        with open(p, "rb") as f:
            return p, sha256(f.read()).hexdigest()

    chunk_files = [p for p in c_dir.iterdir() if p.is_file() and p.resolve() != mpath.resolve()]
    file_hashes: Dict[str, Path] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for p, h in executor.map(_hash_file, chunk_files):
            file_hashes[h] = p

    all_valid = True
    missing_chunks = []
    corrupted_chunks = []

    for i, chunk_info in enumerate(sorted(chunks, key=lambda x: x["index"])):
        if cancel_token and cancel_token():
            raise CancelledError("Verification cancelled by user")

        idx = chunk_info["index"]
        expected_hash = chunk_info["sha256"]
        expected_name = chunk_info.get("filename", f"chunk_{idx:03d}.bin")

        if progress_callback:
            progress_callback(i + 1, len(chunks), "verifying")

        cf_path = c_dir / expected_name
        if cf_path.exists():
            actual_hash = None
            for h, p in file_hashes.items():
                if p == cf_path:
                    actual_hash = h
                    break
            if actual_hash == expected_hash:
                continue
            else:
                corrupted_chunks.append((idx, expected_name, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"))
                all_valid = False
                continue

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


def _decrypt_chunk_worker(
    idx: int,
    raw_chunk: bytes,
    is_encrypted: bool,
    cipher: Optional[Any],
) -> Tuple[int, bytes]:
    """Decrypt single chunk using native AES-256-GCM cipher instance."""
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
            raise DecryptionError("Cryptographic authentication tag mismatch") from e
        return idx, decrypted_data
    return idx, raw_chunk


def extract(
    manifest_path: Optional[str] = None,
    chunks_dir: Optional[str] = None,
    output_dir: Optional[str] = None,
    decrypt_key: Optional[str] = None,
    public_key_path: Optional[str] = None,
    workers: Optional[int] = None,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_token: Optional[Callable[[], bool]] = None,
) -> bool:
    """Verify, decrypt, assemble, and decompress package in one streamlined step."""
    mpath = resolve_manifest_path(manifest_path)
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    manifest = load_manifest(mpath)
    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    # 1. Pre-flight verification
    if not verify(str(mpath), str(c_dir), public_key_path, workers, progress_callback, cancel_token):
        print("[-] Pre-flight verification failed. Aborting extraction.")
        return False

    package_info = manifest.get("package_info", {})
    is_encrypted = package_info.get("encrypted", False)
    source_type = package_info.get("source_type", "file")
    target_name = package_info.get("name", "extracted_output")
    compression_algo = package_info.get("compression", "gzip")

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

    hash_to_path: Dict[str, Path] = {}
    for p in c_dir.iterdir():
        if p.is_file() and p.resolve() != mpath.resolve():
            with open(p, "rb") as f:
                h = sha256(f.read()).hexdigest()
                hash_to_path[h] = p

    out_base = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_base.mkdir(parents=True, exist_ok=True)

    temp_reassembled = out_base / f".tmp_{target_name}.archive"

    try:
        max_workers = workers if workers and workers > 0 else min(32, (os.cpu_count() or 4) * 2)
        max_in_flight = max_workers * 2

        # Resolve paths for all chunks upfront
        chunk_paths: List[Tuple[int, Path]] = []
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

            chunk_paths.append((idx, cf_path))

        # Stream decrypt in bounded sliding window and write sequentially
        with open(temp_reassembled, "wb", buffering=4*1024*1024) as out_f:
            decrypted_buffer: Dict[int, bytes] = {}
            next_write_idx = 0
            total_chunks = len(chunk_paths)

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                in_flight: Dict[concurrent.futures.Future, int] = {}
                submit_iter = iter(chunk_paths)

                while next_write_idx < total_chunks:
                    if cancel_token and cancel_token():
                        raise CancelledError("Extraction cancelled by user")

                    while len(in_flight) < max_in_flight:
                        try:
                            idx, cpath = next(submit_iter)
                            raw_chunk = cpath.read_bytes()
                            fut = executor.submit(_decrypt_chunk_worker, idx, raw_chunk, is_encrypted, cipher)
                            in_flight[fut] = idx
                        except StopIteration:
                            break

                    if not in_flight:
                        break

                    done, _ = concurrent.futures.wait(in_flight.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
                    for d in done:
                        try:
                            c_idx, chunk_bytes = d.result()
                            decrypted_buffer[c_idx] = chunk_bytes
                            del in_flight[d]
                        except Exception:
                            print("[-] Cryptographic authentication layer rejected decryption key or corrupted data.")
                            return False

                    while next_write_idx in decrypted_buffer:
                        out_f.write(decrypted_buffer.pop(next_write_idx))
                        next_write_idx += 1
                        if progress_callback:
                            progress_callback(next_write_idx, total_chunks, "decrypting")

        destination_path = decompress_stream(
            temp_reassembled,
            out_base,
            target_name,
            source_type,
            algorithm=compression_algo,
        )

        print(f"[+] Reassembly and extraction complete -> {destination_path}")
        return True

    finally:
        if temp_reassembled.exists():
            temp_reassembled.unlink()
