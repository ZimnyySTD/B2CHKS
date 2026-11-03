"""Detection, validation, and requirements for native performance backends."""
import hashlib
from b2chks.exceptions import MissingDependencyError

HAVE_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as crypto_AESGCM
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

HAVE_ZSTANDARD = False
try:
    import zstandard as zstd
    HAVE_ZSTANDARD = True
except ImportError:
    HAVE_ZSTANDARD = False

HAVE_SCRYPT = hasattr(hashlib, "scrypt")

def require_cryptography():
    """Raise clear MissingDependencyError if native cryptography library is not installed."""
    if not HAVE_CRYPTOGRAPHY:
        raise MissingDependencyError(
            "Native 'cryptography' library is required for high-performance AES-256-GCM and Ed25519. "
            "Install it via: pip install cryptography"
        )

def require_zstandard():
    """Raise clear MissingDependencyError if native zstandard library is not installed."""
    if not HAVE_ZSTANDARD:
        raise MissingDependencyError(
            "Native 'zstandard' library is required for Zstandard compression. "
            "Install it via: pip install zstandard"
        )

def get_backend_info() -> dict:
    """Return dict describing available performance acceleration backends."""
    return {
        "cryptography": HAVE_CRYPTOGRAPHY,
        "zstandard": HAVE_ZSTANDARD,
        "scrypt": HAVE_SCRYPT,
        "hardware_aes": HAVE_CRYPTOGRAPHY,
    }
