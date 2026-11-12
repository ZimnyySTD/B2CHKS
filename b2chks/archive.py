"""Fast, ordinary ZIP archive support for the no-options CLI mode."""
import os
import shutil
import zipfile
from pathlib import Path
from typing import Callable, Optional

from b2chks.exceptions import CompressionError


def create_zip(
    source: Path,
    output_dir: Path,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    compression_level: int = 9,
) -> Path:
    """Create a conventional ZIP archive without manifests or chunk files."""
    if not 0 <= compression_level <= 9:
        raise ValueError("ZIP compression level must be between 0 and 9")
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{source.name}.zip"
    files = []
    if source.is_file():
        files = [(source, source.name)]
    elif source.is_dir():
        for root, dirs, names in os.walk(source):
            dirs[:] = [name for name in dirs if not (Path(root) / name).is_symlink()]
            for name in names:
                path = Path(root) / name
                if not path.is_symlink():
                    files.append((path, str(path.relative_to(source.parent))))
    else:
        raise FileNotFoundError(f"Source {source} does not exist.")

    total = sum(path.stat().st_size for path, _ in files)
    processed = 0
    temp_path = output_dir / f".{archive_path.name}.tmp"
    try:
        with zipfile.ZipFile(
            temp_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=compression_level,
            allowZip64=True,
        ) as archive:
            for path, arcname in files:
                archive.write(path, arcname)
                processed += path.stat().st_size
                if progress_callback:
                    progress_callback(processed, total, "archiving")
        temp_path.replace(archive_path)
        return archive_path
    finally:
        if temp_path.exists():
            temp_path.unlink()


def extract_zip(
    archive_path: Path,
    output_dir: Path,
    max_output_size: Optional[int] = None,
    max_files: Optional[int] = None,
    max_file_size: Optional[int] = None,
) -> Path:
    """Safely extract a conventional ZIP archive."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stage = output_dir / f".b2chks-{archive_path.stem}.tmp"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    total_size = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if max_files is not None and len(members) > max_files:
                raise CompressionError("Archive exceeds the configured file-count limit")
            for member in members:
                member_path = (stage / member.filename).resolve()
                try:
                    member_path.relative_to(stage.resolve())
                except ValueError as exc:
                    raise CompressionError(f"Unsafe archive path: {member.filename}") from exc
                if member.file_size > 0 and max_file_size is not None and member.file_size > max_file_size:
                    raise CompressionError(f"Archive member exceeds the configured file-size limit: {member.filename}")
                total_size += member.file_size
                if max_output_size is not None and total_size > max_output_size:
                    raise CompressionError("Archive exceeds the configured output-size limit")
            archive.extractall(stage)

        entries = list(stage.iterdir())
        if len(entries) == 1:
            destination = output_dir / entries[0].name
            if destination.exists():
                if destination.is_dir():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            entries[0].replace(destination)
            return destination
        destination = output_dir / archive_path.stem
        if destination.exists():
            shutil.rmtree(destination)
        stage.replace(destination)
        return destination
    finally:
        if stage.exists():
            shutil.rmtree(stage)
