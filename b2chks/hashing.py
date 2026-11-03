"""Optimized hashing utilities using standard library hashlib."""
import hashlib
from pathlib import Path
from typing import Union, BinaryIO

BUFFER_SIZE = 4 * 1024 * 1024  # 4MB buffer for fast I/O streaming

def hash_bytes(data: bytes) -> str:
    """Calculate SHA-256 hexadecimal digest for raw bytes."""
    return hashlib.sha256(data).hexdigest()

def hash_file(file_path: Union[str, Path]) -> str:
    """Calculate SHA-256 hexadecimal digest of a file using buffered streaming."""
    h = hashlib.sha256()
    with open(file_path, "rb", buffering=BUFFER_SIZE) as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def hash_stream(stream: BinaryIO) -> str:
    """Calculate SHA-256 hexadecimal digest from an open binary stream."""
    h = hashlib.sha256()
    while True:
        chunk = stream.read(BUFFER_SIZE)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()
