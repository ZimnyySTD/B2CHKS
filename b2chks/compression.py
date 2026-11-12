"""Zstandard compression adapters for B2CHKS packages."""
import io
import os
import shutil
import tarfile
import concurrent.futures
from pathlib import Path
from typing import Tuple, Optional, Callable, BinaryIO

from b2chks.backends import HAVE_ZSTANDARD
from b2chks.exceptions import CompressionError

if HAVE_ZSTANDARD:
    import zstandard as zstd

STREAM_BUFFER_SIZE = 4 * 1024 * 1024  # 4MB streaming buffer
DEFAULT_ZSTD_LEVEL = 9


class ChunkSink:
    """File-like sink that emits bounded compressed chunks without an archive pass."""

    def __init__(self, out_dir: Path, chunk_size: int, on_chunk):
        self.out_dir = out_dir
        self.chunk_size = chunk_size
        self.on_chunk = on_chunk
        self.buffer = bytearray()
        self.offset = 0

    def writable(self):
        return True

    def write(self, data):
        self.buffer.extend(data)
        available = len(self.buffer) - self.offset
        while available >= self.chunk_size:
            end = self.offset + self.chunk_size
            self.on_chunk(bytes(self.buffer[self.offset:end]))
            self.offset = end
            available -= self.chunk_size
        if self.offset and (self.offset >= 4 * self.chunk_size or self.offset * 2 >= len(self.buffer)):
            del self.buffer[:self.offset]
            self.offset = 0
        return len(data)

    def flush(self):
        return None

    def finish(self):
        if len(self.buffer) > self.offset:
            self.on_chunk(bytes(self.buffer[self.offset:]))
        self.buffer.clear()
        self.offset = 0


def compress_to_chunks(
    source_path: Path,
    out_dir: Path,
    chunk_size: int,
    algorithm: str,
    on_chunk,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    compression_level: int = DEFAULT_ZSTD_LEVEL,
) -> Tuple[int, str]:
    """Compress directly into chunk-sized payloads."""
    if not source_path.exists():
        raise FileNotFoundError(f"Source path {source_path} does not exist")
    algo = algorithm.lower()
    if algo != "zstd":
        raise CompressionError("Only Zstandard compression is supported")
    if not HAVE_ZSTANDARD:
        from b2chks.backends import require_zstandard
        require_zstandard()
    if not -5 <= compression_level <= 22:
        raise ValueError("Zstandard compression level must be between -5 and 22")

    if source_path.is_file():
        source_type = "file"
        total_size = source_path.stat().st_size
    elif source_path.is_dir():
        source_type = "directory"
        total_size = sum(
            fp.stat().st_size
            for root, _, files in os.walk(source_path)
            for fp in (Path(root) / name for name in files)
            if not fp.is_symlink()
        )
    else:
        raise CompressionError(f"Unsupported source path: {source_path}")

    sink = ChunkSink(out_dir, chunk_size, on_chunk)
    if progress_callback:
        progress_callback(0, total_size, "compressing")

    if source_type == "file":
        with open(source_path, "rb", buffering=STREAM_BUFFER_SIZE) as source:
            compressor = zstd.ZstdCompressor(level=compression_level).stream_writer(sink)
            with compressor:
                processed = 0
                while True:
                    buf = source.read(STREAM_BUFFER_SIZE)
                    if not buf:
                        break
                    compressor.write(buf)
                    processed += len(buf)
                    if progress_callback:
                        progress_callback(processed, total_size, "compressing")
    else:
        compressor = zstd.ZstdCompressor(level=compression_level).stream_writer(sink)
        with compressor:
            with tarfile.open(fileobj=compressor, mode="w|") as tar:
                tar.add(str(source_path), arcname=source_path.name)

    sink.finish()
    if progress_callback:
        progress_callback(total_size, total_size, "compressing")
    return total_size, source_type


class ChunkReader:
    """Sequential reader over verified, optionally decrypted chunk payloads."""

    def __init__(self, chunks, read_chunk):
        self.chunks = iter(chunks)
        self.read_chunk = read_chunk
        self.buffer = b""
        self.offset = 0
        self.position = 0

    def readable(self):
        return True

    def read(self, size=-1):
        if size == 0:
            return b""
        if size < 0:
            parts = []
            if self.offset < len(self.buffer):
                parts.append(self.buffer[self.offset:])
            parts.extend(self.read_chunk(chunk) for chunk in self.chunks)
            result = b"".join(parts)
            self.buffer = b""
            self.offset = 0
            self.position += len(result)
            return result

        remaining = len(self.buffer) - self.offset
        while remaining < size:
            try:
                next_chunk = self.read_chunk(next(self.chunks))
            except StopIteration:
                break
            if remaining == 0:
                self.buffer = next_chunk
                self.offset = 0
            else:
                self.buffer = self.buffer[self.offset:] + next_chunk
                self.offset = 0
            remaining = len(self.buffer)
        end = min(self.offset + size, len(self.buffer))
        result = self.buffer[self.offset:end]
        self.offset = end
        self.position += len(result)
        return result

    def seekable(self):
        return False

    def tell(self):
        return self.position


class PrefetchChunkReader(ChunkReader):
    """Sequential reader that hashes/decrypts upcoming chunks concurrently."""

    def __init__(self, chunks, read_chunk, workers=2):
        self.chunks = iter(chunks)
        self.read_chunk = read_chunk
        self.buffer = b""
        self.offset = 0
        self.position = 0
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers))
        self.futures = []
        for _ in range(max(1, workers)):
            self._submit()

    def _submit(self):
        try:
            chunk = next(self.chunks)
        except StopIteration:
            return
        self.futures.append(self.executor.submit(self.read_chunk, chunk))

    def _read_next_chunk(self):
        if not self.futures:
            return None
        future = self.futures.pop(0)
        try:
            result = future.result()
        finally:
            self._submit()
        return result

    def read(self, size=-1):
        if size == 0:
            return b""
        if size < 0:
            parts = []
            if self.offset < len(self.buffer):
                parts.append(self.buffer[self.offset:])
            while True:
                next_chunk = self._read_next_chunk()
                if next_chunk is None:
                    break
                parts.append(next_chunk)
            result = b"".join(parts)
            self.buffer = b""
            self.offset = 0
            self.position += len(result)
            self.close()
            return result

        remaining = len(self.buffer) - self.offset
        while remaining < size:
            next_chunk = self._read_next_chunk()
            if next_chunk is None:
                break
            if remaining == 0:
                self.buffer = next_chunk
                self.offset = 0
            else:
                self.buffer = self.buffer[self.offset:] + next_chunk
                self.offset = 0
            remaining = len(self.buffer)
        end = min(self.offset + size, len(self.buffer))
        result = self.buffer[self.offset:end]
        self.offset = end
        self.position += len(result)
        return result

    def close(self):
        if self.executor is not None:
            self.executor.shutdown(wait=True, cancel_futures=True)
            self.executor = None

def compress_stream(
    source_path: Path,
    output_path: Path,
    algorithm: str = "zstd",
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
    if algo != "zstd":
        raise CompressionError("Only Zstandard compression is supported")
    if not HAVE_ZSTANDARD:
        from b2chks.backends import require_zstandard
        require_zstandard()

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
            raise CompressionError("Only Zstandard compression is supported")

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
            raise CompressionError("Only Zstandard compression is supported")

        if progress_callback:
            progress_callback(total_size, total_size, "compressing")
        return total_size, source_type

    else:
        raise CompressionError(f"Unsupported source path: {source_path}")

def _safe_extract_tar(tar: tarfile.TarFile, target_dir: Path):
    """Safely extract tar archive with strict path traversal protection across all Python versions."""
    target_dir_resolved = target_dir.resolve()
    for member in tar.getmembers():
        # Prevent absolute paths or path traversal with '..'
        member_path = (target_dir / member.name).resolve()
        try:
            member_path.relative_to(target_dir_resolved)
        except ValueError:
            raise CompressionError(f"Attempted path traversal in archive: {member.name}")

        # Check symlinks and hardlinks
        if member.islnk() or member.issym():
            link_target = (member_path.parent / member.linkname).resolve()
            try:
                link_target.relative_to(target_dir_resolved)
            except ValueError:
                raise CompressionError(f"Attempted symlink traversal in archive: {member.name} -> {member.linkname}")

    if hasattr(tarfile, "data_filter"):
        tar.extractall(path=target_dir, filter="data")
    else:
        tar.extractall(path=target_dir)

def decompress_stream(
    archive_path: Path,
    output_dir: Path,
    target_name: str,
    source_type: str,
    algorithm: str = "zstd",
) -> Path:
    """Decompress an archive to target_name inside output_dir with strict path traversal protection."""
    output_dir.mkdir(parents=True, exist_ok=True)
    destination_path = output_dir / target_name
    algo = algorithm.lower()
    if algo != "zstd":
        raise CompressionError("Only Zstandard compression is supported")
    if not HAVE_ZSTANDARD:
        from b2chks.backends import require_zstandard
        require_zstandard()

    if source_type == "file":
        dctx = zstd.ZstdDecompressor()
        with open(archive_path, "rb") as f_in, open(destination_path, "wb") as f_out:
            dctx.copy_stream(f_in, f_out)
    elif source_type == "directory":
        temp_tar = output_dir / f".tmp_{target_name}.tar"
        dctx = zstd.ZstdDecompressor()
        try:
            with open(archive_path, "rb") as f_in, open(temp_tar, "wb") as f_out:
                dctx.copy_stream(f_in, f_out)
            with tarfile.open(temp_tar, "r:") as tar:
                _safe_extract_tar(tar, output_dir)
        finally:
            if temp_tar.exists():
                temp_tar.unlink()
    else:
        raise CompressionError(f"Unknown source type: {source_type}")

    return destination_path


def decompress_reader(
    reader,
    output_dir: Path,
    target_name: str,
    source_type: str,
    algorithm: str = "zstd",
    max_files: Optional[int] = None,
    max_file_size: Optional[int] = None,
) -> Path:
    """Decompress a sequential reader directly into the destination."""
    output_dir.mkdir(parents=True, exist_ok=True)
    destination_path = output_dir / target_name
    algo = algorithm.lower()
    if algo != "zstd":
        raise CompressionError("Only Zstandard compression is supported")
    if not HAVE_ZSTANDARD:
        from b2chks.backends import require_zstandard
        require_zstandard()
    if source_type == "file":
        with zstd.ZstdDecompressor().stream_reader(reader) as decompressed, open(destination_path, "wb") as out:
            shutil.copyfileobj(decompressed, out, STREAM_BUFFER_SIZE)
    elif source_type == "directory":
        with zstd.ZstdDecompressor().stream_reader(reader) as decompressed:
            with tarfile.open(fileobj=decompressed, mode="r|") as tar:
                _safe_extract_tar_stream(tar, output_dir, max_files, max_file_size)
    else:
        raise CompressionError(f"Unknown source type: {source_type}")
    return destination_path


def _safe_extract_tar_stream(tar: tarfile.TarFile, target_dir: Path, max_files=None, max_file_size=None):
    """Safely extract a streaming tar archive member by member."""
    target_dir_resolved = target_dir.resolve()
    file_count = 0
    for member in tar:
        file_count += 1
        if max_files is not None and file_count > max_files:
            raise CompressionError("Archive exceeds the configured file-count limit")
        if max_file_size is not None and member.size > max_file_size:
            raise CompressionError(f"Archive member exceeds the configured file-size limit: {member.name}")
        member_path = (target_dir / member.name).resolve()
        try:
            member_path.relative_to(target_dir_resolved)
        except ValueError as exc:
            raise CompressionError(f"Attempted path traversal in archive: {member.name}") from exc
        if member.islnk() or member.issym():
            link_target = (member_path.parent / member.linkname).resolve()
            try:
                link_target.relative_to(target_dir_resolved)
            except ValueError as exc:
                raise CompressionError(f"Attempted symlink traversal in archive: {member.name}") from exc
        tar.extract(member, path=target_dir, set_attrs=True)
