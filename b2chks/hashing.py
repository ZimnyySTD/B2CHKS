"""Optimized streaming hashing utilities using standard library hashlib."""
import hashlib
from pathlib import Path
from typing import Union, BinaryIO

STREAM_CHUNK_BUFFER = 1024 * 1024  # 1MB buffer for streaming hash updates

def hash_bytes(data: bytes) -> str:
    """Calculate SHA-256 hexadecimal digest for raw bytes."""
    return hashlib.sha256(data).hexdigest()

def hash_file(file_path: Union[str, Path]) -> str:
    """Calculate SHA-256 hexadecimal digest of a file using bounded streaming updates."""
    h = hashlib.sha256()
    with open(file_path, "rb", buffering=STREAM_CHUNK_BUFFER) as f:
        while True:
            chunk = f.read(STREAM_CHUNK_BUFFER)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def hash_stream(stream: BinaryIO) -> str:
    """Calculate SHA-256 hexadecimal digest from an open binary stream."""
    h = hashlib.sha256()
    while True:
        chunk = stream.read(STREAM_CHUNK_BUFFER)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()
