"""Native-only AES-256-GCM encryption & scrypt / PBKDF2 key derivation."""
import hashlib
import os
from typing import Optional, Dict, Any

from b2chks.backends import HAVE_CRYPTOGRAPHY, require_cryptography
from b2chks.exceptions import DecryptionError

if HAVE_CRYPTOGRAPHY:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as crypto_AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16
DEFAULT_KDF = "scrypt"
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 67108864
PBKDF2_ITERATIONS = 100_000


def derive_aes_key(passphrase: str, salt: bytes, kdf_name: str = DEFAULT_KDF, kdf_params: Optional[Dict[str, Any]] = None) -> bytes:
    """Derive 256-bit AES key using native memory-hard scrypt or PBKDF2."""
    pw_bytes = passphrase.encode("utf-8")
    kdf_lower = kdf_name.lower()
    if kdf_lower == "scrypt" and hasattr(hashlib, "scrypt"):
        params = kdf_params or {}
        n = params.get("n", SCRYPT_N)
        r = params.get("r", SCRYPT_R)
        p = params.get("p", SCRYPT_P)
        maxmem = params.get("maxmem", SCRYPT_MAXMEM)
        try:
            return hashlib.scrypt(pw_bytes, salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=32)
        except Exception:
            return hashlib.scrypt(pw_bytes, salt=salt, n=16384, r=8, p=1, maxmem=67108864, dklen=32)
    else:
        params = kdf_params or {}
        iterations = params.get("iterations", PBKDF2_ITERATIONS)
        return hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iterations, dklen=32)


def get_aes_gcm_cipher(key: bytes):
    """Instantiate and return native AESGCM cipher."""
    require_cryptography()
    return crypto_AESGCM(key)


def encrypt_aes_gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Encrypt payload using native AES-256-GCM."""
    require_cryptography()
    cipher = crypto_AESGCM(key)
    return cipher.encrypt(nonce, data, associated_data=aad)


def decrypt_aes_gcm(key: bytes, nonce: bytes, data_with_tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate payload using native AES-256-GCM."""
    require_cryptography()
    cipher = crypto_AESGCM(key)
    try:
        return cipher.decrypt(nonce, data_with_tag, associated_data=aad)
    except Exception as e:
        raise DecryptionError("Cryptographic authentication tag mismatch") from e
