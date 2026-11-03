"""
B2CHKS: High-performance file packaging, chunking, compression, and distribution protocol.
"""
from b2chks.engine import B2CHKS, PackConfig, ExtractConfig
from b2chks.exceptions import (
    B2CHKSError,
    ManifestError,
    IntegrityError,
    AuthenticationError,
    DecryptionError,
    ChunkError,
    CompressionError,
    CancelledError,
)
from b2chks.extractor import verify, extract, resolve_manifest_path
from b2chks.packer import pack
from b2chks.signing import generate_keypair, sign_data, verify_signature
from b2chks.encryption import derive_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from b2chks.chunking import parse_size
from b2chks.manifest import load_manifest, write_manifest, get_canonical_json_bytes
from b2chks.backends import get_backend_info, HAVE_CRYPTOGRAPHY, HAVE_ZSTANDARD
from b2chks.backends import require_cryptography, require_zstandard

def main(*args, **kwargs):
    """Lazy CLI entrypoint to avoid circular import issues."""
    from cli.main import main as _cli_main
    return _cli_main(*args, **kwargs)

PROTOCOL_VERSION = "b2chks"

__all__ = [
    "main",
    "B2CHKS",
    "PackConfig",
    "ExtractConfig",
    "pack",
    "verify",
    "extract",
    "resolve_manifest_path",
    "generate_keypair",
    "derive_aes_key",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "sign_data",
    "verify_signature",
    "parse_size",
    "load_manifest",
    "write_manifest",
    "get_canonical_json_bytes",
    "get_backend_info",
    "HAVE_CRYPTOGRAPHY",
    "HAVE_ZSTANDARD",
    "PROTOCOL_VERSION",
    "B2CHKSError",
    "ManifestError",
    "IntegrityError",
    "AuthenticationError",
    "DecryptionError",
    "ChunkError",
    "CompressionError",
    "CancelledError",
]
