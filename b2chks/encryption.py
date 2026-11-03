"""AES-256-GCM encryption & scrypt / PBKDF2 key derivation."""
import hashlib
import os
from typing import Optional, Dict, Any

from b2chks.backends import HAVE_CRYPTOGRAPHY
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

# Pure-Python AES-256-GCM implementation
_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
_AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _aes_xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1)

def _aes_key_expansion_256(key: bytes):
    w = [int.from_bytes(key[4*i:4*i+4], "big") for i in range(8)]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            temp = ((temp << 8) & 0xffffffff) | (temp >> 24)
            b0 = _AES_SBOX[(temp >> 24) & 0xff]
            b1 = _AES_SBOX[(temp >> 16) & 0xff]
            b2 = _AES_SBOX[(temp >> 8) & 0xff]
            b3 = _AES_SBOX[temp & 0xff]
            temp = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) ^ (_AES_RCON[i // 8] << 24)
        elif i % 8 == 4:
            b0 = _AES_SBOX[(temp >> 24) & 0xff]
            b1 = _AES_SBOX[(temp >> 16) & 0xff]
            b2 = _AES_SBOX[(temp >> 8) & 0xff]
            b3 = _AES_SBOX[temp & 0xff]
            temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        w.append(w[i - 8] ^ temp)
    round_keys = []
    for r in range(15):
        rk = []
        for c in range(4):
            val = w[r * 4 + c]
            rk.extend([(val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff])
        round_keys.append(bytes(rk))
    return round_keys

def _aes_encrypt_block(block: bytes, round_keys):
    state = list(block)
    for i in range(16):
        state[i] ^= round_keys[0][i]
    for r in range(1, 14):
        for i in range(16):
            state[i] = _AES_SBOX[state[i]]
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        for c in range(4):
            i = c * 4
            s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
            t = s0 ^ s1 ^ s2 ^ s3
            state[i] ^= t ^ _aes_xtime(s0 ^ s1)
            state[i+1] ^= t ^ _aes_xtime(s1 ^ s2)
            state[i+2] ^= t ^ _aes_xtime(s2 ^ s3)
            state[i+3] ^= t ^ _aes_xtime(s3 ^ s0)
        rk = round_keys[r]
        for i in range(16):
            state[i] ^= rk[i]
    for i in range(16):
        state[i] = _AES_SBOX[state[i]]
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
    rk = round_keys[14]
    for i in range(16):
        state[i] ^= rk[i]
    return bytes(state)

_GCM_R_POLY = 0xe1000000000000000000000000000000

def _ghash_multiply(x: int, y: int) -> int:
    v = y
    z = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_R_POLY
        else:
            v >>= 1
    return z

def _ghash(H_int: int, data: bytes, aad: bytes = b"") -> bytes:
    pad_aad = (-len(aad)) % 16
    pad_data = (-len(data)) % 16
    stream = aad + (b"\x00" * pad_aad) + data + (b"\x00" * pad_data)
    stream += (len(aad) * 8).to_bytes(8, "big") + (len(data) * 8).to_bytes(8, "big")
    y = 0
    for i in range(0, len(stream), 16):
        block = int.from_bytes(stream[i:i+16], "big")
        y = _ghash_multiply(y ^ block, H_int)
    return y.to_bytes(16, "big")

def _py_aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    rk = _aes_key_expansion_256(key)
    H = _aes_encrypt_block(b"\x00" * 16, rk)
    H_int = int.from_bytes(H, "big")
    J0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = bytearray(len(plaintext))
    cnt = 2
    for i in range(0, len(plaintext), 16):
        ctr_block = nonce + cnt.to_bytes(4, "big")
        ks = _aes_encrypt_block(ctr_block, rk)
        chunk = plaintext[i:i+16]
        for j in range(len(chunk)):
            ciphertext[i+j] = chunk[j] ^ ks[j]
        cnt += 1
    S = _ghash(H_int, bytes(ciphertext), aad)
    T_mask = _aes_encrypt_block(J0, rk)
    tag = bytes(a ^ b for a, b in zip(S, T_mask))
    return bytes(ciphertext) + tag

def _py_aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes = b"") -> bytes:
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Invalid ciphertext length")
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    rk = _aes_key_expansion_256(key)
    H = _aes_encrypt_block(b"\x00" * 16, rk)
    H_int = int.from_bytes(H, "big")
    J0 = nonce + b"\x00\x00\x00\x01"
    S = _ghash(H_int, ciphertext, aad)
    T_mask = _aes_encrypt_block(J0, rk)
    expected_tag = bytes(a ^ b for a, b in zip(S, T_mask))
    if tag != expected_tag:
        raise DecryptionError("Authentication tag mismatch")
    plaintext = bytearray(len(ciphertext))
    cnt = 2
    for i in range(0, len(ciphertext), 16):
        ctr_block = nonce + cnt.to_bytes(4, "big")
        ks = _aes_encrypt_block(ctr_block, rk)
        chunk = ciphertext[i:i+16]
        for j in range(len(chunk)):
            plaintext[i+j] = chunk[j] ^ ks[j]
        cnt += 1
    return bytes(plaintext)

def derive_aes_key(passphrase: str, salt: bytes, kdf_name: str = DEFAULT_KDF, kdf_params: Optional[Dict[str, Any]] = None) -> bytes:
    """Derive 256-bit AES key using memory-hard scrypt or PBKDF2."""
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

def encrypt_aes_gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Encrypt payload using AES-256-GCM."""
    if HAVE_CRYPTOGRAPHY:
        aesgcm = crypto_AESGCM(key)
        return aesgcm.encrypt(nonce, data, associated_data=aad)
    return _py_aes_gcm_encrypt(key, nonce, data, aad=aad)

def decrypt_aes_gcm(key: bytes, nonce: bytes, data_with_tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate payload using AES-256-GCM."""
    if HAVE_CRYPTOGRAPHY:
        try:
            aesgcm = crypto_AESGCM(key)
            return aesgcm.decrypt(nonce, data_with_tag, associated_data=aad)
        except Exception as e:
            raise DecryptionError("Cryptographic authentication tag mismatch") from e
    try:
        return _py_aes_gcm_decrypt(key, nonce, data_with_tag, aad=aad)
    except Exception as e:
        raise DecryptionError("Cryptographic authentication tag mismatch") from e
