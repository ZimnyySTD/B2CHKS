"""Chunk parsing, streaming, and metadata management."""
from pathlib import Path
from typing import Dict, Any

from b2chks.exceptions import ChunkError

def parse_size(size_str: str) -> int:
    """Parse size string with multipliers (b, k, m, g, t) into integer bytes."""
    if not size_str:
        raise ValueError("Chunk size cannot be empty")
    size_str = str(size_str).strip().lower()
    units = {
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "m": 1024 * 1024,
        "mb": 1024 * 1024,
        "g": 1024 * 1024 * 1024,
        "gb": 1024 * 1024 * 1024,
        "t": 1024 * 1024 * 1024 * 1024,
        "tb": 1024 * 1024 * 1024 * 1024,
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
