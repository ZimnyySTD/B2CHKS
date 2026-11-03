"""High-level B2CHKS SDK Engine and configuration objects."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, Tuple, Union

from b2chks.extractor import verify, extract
from b2chks.packer import pack
from b2chks.signing import generate_keypair

@dataclass
class PackConfig:
    """Configuration parameters for packaging."""
    chunk_size: str = "500m"
    output_dir: Optional[str] = None
    encrypt_key: Optional[str] = None
    private_key: Optional[str] = None
    author: Optional[str] = None
    compression: str = "gzip"
    kdf: str = "scrypt"
    workers: Optional[int] = None
    generate_key: bool = False

@dataclass
class ExtractConfig:
    """Configuration parameters for extraction."""
    chunks_dir: Optional[str] = None
    output_dir: Optional[str] = None
    decrypt_key: Optional[str] = None
    public_key: Optional[str] = None
    workers: Optional[int] = None

class B2CHKS:
    """
    High-level, reusable Python SDK for B2CHKS.
    Designed for embedding in desktop game launchers, backup tools, web services, and deployment pipelines.
    """

    @staticmethod
    def keygen(author: str = "author", out_dir: str = ".") -> Tuple[str, str]:
        """Generate Ed25519 signing keypair (`private.pem` and `public.pem`)."""
        return generate_keypair(author=author, out_dir=out_dir)

    @staticmethod
    def pack(
        source: Union[str, Path],
        chunk_size: str = "500m",
        output_dir: Optional[Union[str, Path]] = None,
        encrypt_key: Optional[str] = None,
        private_key: Optional[Union[str, Path]] = None,
        author: Optional[str] = None,
        compression: str = "gzip",
        kdf: str = "scrypt",
        workers: Optional[int] = None,
        generate_key: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> Path:
        """Compress, chunk, encrypt, and sign a file or directory."""
        return pack(
            source=str(source),
            chunk_size_str=chunk_size,
            output_dir=str(output_dir) if output_dir else None,
            encrypt_key=encrypt_key,
            private_key_path=str(private_key) if private_key else None,
            author=author,
            compression=compression,
            kdf=kdf,
            workers=workers,
            generate_key=generate_key,
            progress_callback=progress_callback,
            cancel_token=cancel_token,
        )

    @staticmethod
    def verify(
        manifest: Optional[Union[str, Path]] = None,
        chunks_dir: Optional[Union[str, Path]] = None,
        public_key: Optional[Union[str, Path]] = None,
        workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """Verify chunk inventory, hashes, and author signature."""
        return verify(
            manifest_path=str(manifest) if manifest else None,
            chunks_dir=str(chunks_dir) if chunks_dir else None,
            public_key_path=str(public_key) if public_key else None,
            workers=workers,
            progress_callback=progress_callback,
            cancel_token=cancel_token,
        )

    @staticmethod
    def extract(
        manifest: Optional[Union[str, Path]] = None,
        chunks_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        decrypt_key: Optional[str] = None,
        public_key: Optional[Union[str, Path]] = None,
        workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """Verify, decrypt, reassemble, and decompress package in one go."""
        return extract(
            manifest_path=str(manifest) if manifest else None,
            chunks_dir=str(chunks_dir) if chunks_dir else None,
            output_dir=str(output_dir) if output_dir else None,
            decrypt_key=decrypt_key,
            public_key_path=str(public_key) if public_key else None,
            workers=workers,
            progress_callback=progress_callback,
            cancel_token=cancel_token,
        )
