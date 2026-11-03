"""Compression adapters supporting gzip, zlib, and Zstandard (zstd)."""
import gzip
import io
import os
import shutil
import tarfile
from pathlib import Path
from typing import Tuple, Optional, Callable, BinaryIO

from b2chks.backends import HAVE_ZSTANDARD
from b2chks.exceptions import CompressionError

if HAVE_ZSTANDARD:
    import zstandard as zstd

STREAM_BUFFER_SIZE = 4 * 1024 * 1024  # 4MB streaming buffer

def compress_stream(
    source_path: Path,
    output_path: Path,
    algorithm: str = "gzip",
    compress_level: int = 1,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> Tuple[int, str]:
    """
    Compress a single file or directory tree into output_path.
    Returns (uncompressed_total_bytes, source_type).
    """
    if not source_path.exists():
        raise FileNotFoundError(f"Source path {source_path} does not exist")

    algo = algorithm.lower()
    if algo not in ["gzip", "zstd"]:
        algo = "gzip"

    if algo == "zstd" and not HAVE_ZSTANDARD:
        algo = "gzip"

    if source_path.is_file():
        source_type = "file"
        total_size = source_path.stat().st_size
        bytes_processed = 0

        if algo == "zstd":
            cctx = zstd.ZstdCompressor(level=compress_level if compress_level > 0 else 3)
            with open(source_path, "rb", buffering=STREAM_BUFFER_SIZE) as f_in, open(output_path, "wb", buffering=STREAM_BUFFER_SIZE) as f_out:
                with cctx.stream_writer(f_out) as compressor:
                    while True:
                        buf = f_in.read(STREAM_BUFFER_SIZE)
                        if not buf:
                            break
                        compressor.write(buf)
                        bytes_processed += len(buf)
                        if progress_callback:
                            progress_callback(bytes_processed, total_size, "compressing")
        else:
            with open(source_path, "rb", buffering=STREAM_BUFFER_SIZE) as f_in, gzip.open(output_path, "wb", compresslevel=compress_level) as f_out:
                while True:
                    buf = f_in.read(STREAM_BUFFER_SIZE)
                    if not buf:
                        break
                    f_out.write(buf)
                    bytes_processed += len(buf)
                    if progress_callback:
                        progress_callback(bytes_processed, total_size, "compressing")

        return total_size, source_type

    elif source_path.is_dir():
        source_type = "directory"
        total_size = 0
        for root, _, files in os.walk(source_path):
            for file in files:
                fp = Path(root) / file
                if not fp.is_symlink():
                    total_size += fp.stat().st_size

        if progress_callback:
            progress_callback(0, total_size, "compressing")

        if algo == "zstd":
            cctx = zstd.ZstdCompressor(level=compress_level if compress_level > 0 else 3)
            with open(output_path, "wb", buffering=STREAM_BUFFER_SIZE) as f_out:
                with cctx.stream_writer(f_out) as compressor:
                    with tarfile.open(fileobj=compressor, mode="w|") as tar:
                        tar.add(str(source_path), arcname=source_path.name)
        else:
            with tarfile.open(output_path, "w:gz", compresslevel=compress_level) as tar:
                tar.add(str(source_path), arcname=source_path.name)

        if progress_callback:
            progress_callback(total_size, total_size, "compressing")
        return total_size, source_type

    else:
        raise CompressionError(f"Unsupported source path: {source_path}")

def decompress_stream(
    archive_path: Path,
    output_dir: Path,
    target_name: str,
    source_type: str,
    algorithm: str = "gzip",
) -> Path:
    """Decompress an archive to target_name inside output_dir with path traversal protection."""
    output_dir.mkdir(parents=True, exist_ok=True)
    destination_path = output_dir / target_name
    algo = algorithm.lower()

    if source_type == "file":
        if algo == "zstd" and HAVE_ZSTANDARD:
            dctx = zstd.ZstdDecompressor()
            with open(archive_path, "rb") as f_in, open(destination_path, "wb") as f_out:
                dctx.copy_stream(f_in, f_out)
        else:
            with gzip.open(archive_path, "rb") as gz_in, open(destination_path, "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)
    elif source_type == "directory":
        if algo == "zstd" and HAVE_ZSTANDARD:
            dctx = zstd.ZstdDecompressor()
            with open(archive_path, "rb") as f_in:
                with dctx.stream_reader(f_in) as reader:
                    with tarfile.open(fileobj=reader, mode="r|") as tar:
                        if hasattr(tarfile, "data_filter"):
                            tar.extractall(path=output_dir, filter="data")
                        else:
                            tar.extractall(path=output_dir)
        else:
            with tarfile.open(archive_path, "r:gz") as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=output_dir, filter="data")
                else:
                    tar.extractall(path=output_dir)
    else:
        raise CompressionError(f"Unknown source type: {source_type}")

    return destination_path
