"""Detection and status of native performance backends."""

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

def get_backend_info() -> dict:
    """Return dict describing available performance acceleration backends."""
    return {
        "cryptography": HAVE_CRYPTOGRAPHY,
        "zstandard": HAVE_ZSTANDARD,
        "scrypt": True,
        "hardware_aes": HAVE_CRYPTOGRAPHY,
    }
