"""Chunk parsing, streaming, and byte-budgeted memory management."""
import threading
from pathlib import Path
from typing import Dict, Any

class ByteBudget:
    """
    Thread-safe byte budget tracker to prevent memory exhaustion
    by bounding the total unwritten/inflight chunk bytes in memory.
    """
    def __init__(self, max_bytes: int):
        self.max_bytes = max(1024 * 1024, max_bytes)
        self.current_bytes = 0
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)

    def acquire(self, nbytes: int):
        """Block until nbytes can be budgeted within max_bytes."""
        with self.condition:
            while self.current_bytes + nbytes > self.max_bytes and self.current_bytes > 0:
                self.condition.wait()
            self.current_bytes += nbytes

    def release(self, nbytes: int):
        """Release budgeted bytes and notify waiting threads."""
        with self.condition:
            self.current_bytes = max(0, self.current_bytes - nbytes)
            self.condition.notify_all()


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
