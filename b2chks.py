#!/usr/bin/env python3
"""
B2CHKS: High-performance file packaging, chunking, compression, and secure distribution protocol.
Pure-Python zero-dependency implementation with optional cryptography acceleration.
Cross-platform support for Linux, macOS, and Windows.
"""

import argparse
import base64
import getpass
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
from hashlib import sha256
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

PROTOCOL_VERSION = "b2chks"
PBKDF2_ITERATIONS = 100_000
NONCE_SIZE = 12
TAG_SIZE = 16

# Try loading external cryptography library if available; otherwise use built-in pure Python
HAVE_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as crypto_AESGCM
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


# ==============================================================================
# Pure Python Ed25519 Implementation (RFC 8032)
# ==============================================================================

_ED_B = 256
_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493

def _ed_H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()

def _ed_expmod(b: int, e: int, m: int) -> int:
    return pow(b, e, m)

def _ed_inv(x: int) -> int:
    return _ed_expmod(x, _ED_Q - 2, _ED_Q)

_ED_D = -121665 * _ed_inv(121666)
_ED_I = _ed_expmod(2, (_ED_Q - 1) // 4, _ED_Q)

def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * _ed_inv(_ED_D * y * y + 1)
    x = _ed_expmod(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if x % 2 != 0:
        x = _ED_Q - x
    return x

_ED_BY = 4 * _ed_inv(5)
_ED_BX = _ed_xrecover(_ED_BY)
_ED_BASE = [_ED_BX % _ED_Q, _ED_BY % _ED_Q]

def _ed_edwards(P: List[int], Q: List[int]) -> List[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + _ED_D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - _ED_D * x1 * x2 * y1 * y2)
    return [x3 % _ED_Q, y3 % _ED_Q]

def _ed_scalarmult(P: List[int], e: int) -> List[int]:
    if e == 0:
        return [0, 1]
    Q = _ed_scalarmult(P, e // 2)
    Q = _ed_edwards(Q, Q)
    if e & 1:
        Q = _ed_edwards(Q, P)
    return Q

def _ed_encodeint(y: int) -> bytes:
    return int(y).to_bytes(32, "little")

def _ed_encodepoint(P: List[int]) -> bytes:
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(_ED_B - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_ED_B // 8))

def _ed_bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1

def _ed_publickey(sk: bytes) -> bytes:
    h = _ed_H(sk)
    a = 2**(_ED_B - 2) + sum(2**i * _ed_bit(h, i) for i in range(3, _ED_B - 2))
    A = _ed_scalarmult(_ED_BASE, a)
    return _ed_encodepoint(A)

def _ed_Hint(m: bytes) -> int:
    return int.from_bytes(_ed_H(m), "little")

def _ed_sign(m: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _ed_H(sk)
    a = 2**(_ED_B - 2) + sum(2**i * _ed_bit(h, i) for i in range(3, _ED_B - 2))
    r = _ed_Hint(bytes([h[i] for i in range(_ED_B // 8, _ED_B // 4)]) + m)
    R = _ed_scalarmult(_ED_BASE, r)
    S = (r + _ed_Hint(_ed_encodepoint(R) + pk + m) * a) % _ED_L
    return _ed_encodepoint(R) + _ed_encodeint(S)

def _ed_isoncurve(P: List[int]) -> bool:
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_Q == 0

def _ed_decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")

def _ed_decodepoint(s: bytes) -> List[int]:
    y = sum(2**i * _ed_bit(s, i) for i in range(0, _ED_B - 1))
    x = _ed_xrecover(y)
    if x & 1 != _ed_bit(s, _ED_B - 1):
        x = _ED_Q - x
    P = [x, y]
    if not _ed_isoncurve(P):
        raise ValueError("Decoding point that is not on curve")
    return P

def _ed_verify(s: bytes, m: bytes, pk: bytes) -> bool:
    if len(s) != _ED_B // 4 or len(pk) != _ED_B // 8:
        return False
    try:
        R = _ed_decodepoint(s[:_ED_B // 8])
        A = _ed_decodepoint(pk)
        S = _ed_decodeint(s[_ED_B // 8:])
        h = _ed_Hint(_ed_encodepoint(R) + pk + m)
        v1 = _ed_scalarmult(_ED_BASE, S)
        v2 = _ed_edwards(R, _ed_scalarmult(A, h))
        return v1 == v2
    except Exception:
        return False


# Standard PKCS#8 and SubjectPublicKeyInfo ASN.1 DER fixed headers for Ed25519
_ED25519_PKCS8_PRIV_HEADER = bytes.fromhex("302e020100300506032b657004220420")
_ED25519_SPKI_PUB_HEADER = bytes.fromhex("302a300506032b6570032100")

def _format_pem(header: str, body_bytes: bytes) -> str:
    b64 = base64.b64encode(body_bytes).decode("ascii")
    lines = [f"-----BEGIN {header}-----"]
    for i in range(0, len(b64), 64):
        lines.append(b64[i:i+64])
    lines.append(f"-----END {header}-----\n")
    return "\n".join(lines)

def _parse_pem(pem_str: str) -> bytes:
    clean_lines = []
    for line in pem_str.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("-----"):
            continue
        clean_lines.append(line)
    return base64.b64decode("".join(clean_lines))


# ==============================================================================
# Pure Python AES-256-GCM Implementation (NIST SP 800-38D)
# ==============================================================================

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

def _aes_key_expansion_256(key: bytes) -> List[bytes]:
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

def _aes_encrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
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
        raise ValueError("Authentication tag mismatch")
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


# ==============================================================================
# Unified Cryptographic Abstractions
# ==============================================================================

def derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 256-bit key from passphrase using PBKDF2-HMAC-SHA256 (standard library)."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)

def encrypt_aes_gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Encrypt using AES-256-GCM. Uses cryptography if available, else pure Python."""
    if HAVE_CRYPTOGRAPHY:
        aesgcm = crypto_AESGCM(key)
        return aesgcm.encrypt(nonce, data, associated_data=aad)
    return _py_aes_gcm_encrypt(key, nonce, data, aad=aad)

def decrypt_aes_gcm(key: bytes, nonce: bytes, data_with_tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt using AES-256-GCM. Uses cryptography if available, else pure Python."""
    if HAVE_CRYPTOGRAPHY:
        aesgcm = crypto_AESGCM(key)
        return aesgcm.decrypt(nonce, data_with_tag, associated_data=aad)
    return _py_aes_gcm_decrypt(key, nonce, data_with_tag, aad=aad)

def generate_keypair(author: str = "author", out_dir: str = ".") -> Tuple[str, str]:
    """Generate Ed25519 keypair and save to private.pem and public.pem."""
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    priv_file = out_path / "private.pem"
    pub_file = out_path / "public.pem"

    if HAVE_CRYPTOGRAPHY:
        private_key = crypto_ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_bytes = private_key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(priv_file, "wb") as f:
            f.write(priv_bytes)
        with open(pub_file, "wb") as f:
            f.write(pub_bytes)
    else:
        seed = os.urandom(32)
        pub = _ed_publickey(seed)
        priv_der = _ED25519_PKCS8_PRIV_HEADER + seed
        pub_der = _ED25519_SPKI_PUB_HEADER + pub
        with open(priv_file, "w", encoding="utf-8") as f:
            f.write(_format_pem("PRIVATE KEY", priv_der))
        with open(pub_file, "w", encoding="utf-8") as f:
            f.write(_format_pem("PUBLIC KEY", pub_der))

    return str(priv_file), str(pub_file)

def load_private_key_seed(priv_path: Path) -> Optional[bytes]:
    """Load 32-byte Ed25519 seed from private key PEM or raw bytes."""
    try:
        content = priv_path.read_bytes()
        # If PEM
        if b"BEGIN" in content:
            der = _parse_pem(content.decode("utf-8", errors="ignore"))
            if len(der) >= 32:
                return der[-32:]
        elif len(content) == 32:
            return content
    except Exception:
        pass
    return None

def load_public_key_bytes(pub_source: Any) -> Optional[bytes]:
    """Load 32-byte Ed25519 public key bytes from PEM file, hex string, or raw bytes."""
    try:
        if isinstance(pub_source, (str, Path)) and Path(pub_source).exists():
            content = Path(pub_source).read_bytes()
            if b"BEGIN" in content:
                der = _parse_pem(content.decode("utf-8", errors="ignore"))
                if len(der) >= 32:
                    return der[-32:]
            elif len(content) == 32:
                return content
        if isinstance(pub_source, str):
            clean = pub_source.strip()
            if len(clean) == 64:
                return bytes.fromhex(clean)
            if "BEGIN" in clean:
                der = _parse_pem(clean)
                if len(der) >= 32:
                    return der[-32:]
    except Exception:
        pass
    return None

def sign_data(data: bytes, priv_path: Path) -> Optional[Tuple[str, str]]:
    """Sign data using Ed25519 key. Returns (signature_hex, public_key_hex)."""
    seed = load_private_key_seed(priv_path)
    if not seed:
        return None
    pub = _ed_publickey(seed)
    sig = _ed_sign(data, seed, pub)
    return sig.hex(), pub.hex()

def verify_signature(data: bytes, signature_hex: str, pub_source: Any) -> bool:
    """Verify Ed25519 signature."""
    try:
        pub = load_public_key_bytes(pub_source)
        if not pub:
            return False
        sig = bytes.fromhex(signature_hex)
        return _ed_verify(sig, data, pub)
    except Exception:
        return False


# ==============================================================================
# Helper Utilities
# ==============================================================================

def parse_size(size_str: str) -> int:
    """Parse size string like 100k, 500m, 2g, 1024 into integer bytes."""
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

def get_canonical_json_bytes(manifest_dict: Dict[str, Any]) -> bytes:
    """Produce deterministic canonical JSON bytes excluding the signature field."""
    clean = json.loads(json.dumps(manifest_dict))
    if "security" in clean and "signature" in clean["security"]:
        del clean["security"]["signature"]
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")

def compress_source_to_stream(source_path: Path, temp_file_path: Path) -> Tuple[int, str]:
    """Compress file or directory into temp_file_path using gzip stream."""
    if source_path.is_file():
        source_type = "file"
        total_size = source_path.stat().st_size
        with open(source_path, "rb") as f_in, gzip.open(temp_file_path, "wb", compresslevel=6) as f_out:
            shutil.copyfileobj(f_in, f_out)
        return total_size, source_type
    elif source_path.is_dir():
        source_type = "directory"
        total_size = 0
        for root, _, files in os.walk(source_path):
            for file in files:
                fp = Path(root) / file
                if not fp.is_symlink():
                    total_size += fp.stat().st_size

        with tarfile.open(temp_file_path, "w:gz", compresslevel=6) as tar:
            tar.add(str(source_path), arcname=source_path.name)
        return total_size, source_type
    else:
        raise FileNotFoundError(f"Source path {source_path} does not exist")

def resolve_manifest_path(input_path: Optional[str] = None) -> Path:
    """Resolve manifest file path, handling directories, None, or explicit filenames."""
    if not input_path or input_path == ".":
        cand = Path("manifest.json").resolve()
        if cand.exists():
            return cand
        cand = Path("dist/manifest.json").resolve()
        if cand.exists():
            return cand
        return Path("manifest.json").resolve()

    p = Path(input_path).resolve()
    if p.is_dir():
        cand = p / "manifest.json"
        if cand.exists():
            return cand
        return cand
    return p


# ==============================================================================
# Core Operations: Pack, Verify, Extract
# ==============================================================================

def pack(
    source: str,
    chunk_size_str: str,
    output_dir: Optional[str] = None,
    encrypt_key: Optional[str] = None,
    private_key_path: Optional[str] = None,
    author: Optional[str] = None,
    generate_key: bool = False,
) -> Path:
    """Pack a file or directory into compressed, optionally encrypted chunks with manifest."""
    source_path = Path(source).resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Source {source} does not exist.")

    chunk_size = parse_size(chunk_size_str)
    out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Key generation request or detection
    priv_file = private_key_path
    if generate_key or (priv_file and not Path(priv_file).exists() and priv_file == "auto"):
        print(f"[*] Generating new developer Ed25519 keypair for author '{author or 'author'}'...")
        priv_str, _ = generate_keypair(author or "author", str(out_dir))
        priv_file = priv_str

    if not priv_file:
        cand = out_dir / "private.pem"
        if cand.exists():
            priv_file = str(cand)
        elif Path("private.pem").exists():
            priv_file = str(Path("private.pem").resolve())

    # Temporary compressed archive
    temp_archive = out_dir / f".tmp_{source_path.name}.archive"

    print(f"[*] Compressing source '{source_path.name}'...")
    total_uncompressed_size, source_type = compress_source_to_stream(source_path, temp_archive)
    compressed_size = temp_archive.stat().st_size
    print(f"[*] Compressed {total_uncompressed_size} bytes -> {compressed_size} bytes.")

    is_encrypted = bool(encrypt_key)
    salt_hex = None
    aes_key = None
    if is_encrypted:
        salt = os.urandom(16)
        salt_hex = salt.hex()
        aes_key = derive_aes_key(encrypt_key, salt)
        if chunk_size > (NONCE_SIZE + TAG_SIZE):
            read_chunk_size = chunk_size - (NONCE_SIZE + TAG_SIZE)
        else:
            read_chunk_size = chunk_size
    else:
        read_chunk_size = chunk_size

    chunks_meta = []
    chunk_index = 0

    print(f"[*] Splitting into chunks of target size {chunk_size} bytes...")
    with open(temp_archive, "rb") as src_f:
        while True:
            chunk_data = src_f.read(read_chunk_size)
            if not chunk_data:
                if chunk_index == 0:
                    chunk_data = b""
                else:
                    break

            if is_encrypted:
                nonce = os.urandom(NONCE_SIZE)
                ciphertext_with_tag = encrypt_aes_gcm(
                    aes_key,
                    nonce,
                    chunk_data,
                    aad=chunk_index.to_bytes(4, "big"),
                )
                file_bytes = nonce + ciphertext_with_tag
            else:
                file_bytes = chunk_data

            chunk_filename = f"chunk_{chunk_index:03d}.bin"
            chunk_path = out_dir / chunk_filename
            with open(chunk_path, "wb") as cf:
                cf.write(file_bytes)

            chunk_hash = sha256(file_bytes).hexdigest()
            chunks_meta.append({
                "index": chunk_index,
                "filename": chunk_filename,
                "size": len(file_bytes),
                "sha256": chunk_hash,
            })

            chunk_index += 1
            if not chunk_data:
                break

    if temp_archive.exists():
        temp_archive.unlink()

    package_info: Dict[str, Any] = {
        "name": source_path.name,
        "source_type": source_type,
        "total_size_bytes": total_uncompressed_size,
        "chunk_size_bytes": chunk_size,
        "total_chunks": len(chunks_meta),
        "encrypted": is_encrypted,
    }

    manifest: Dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "package_info": package_info,
        "security": {
            "developer_id": author or "",
            "public_key": "",
            "signature": "",
        },
        "chunks": chunks_meta,
    }

    if is_encrypted:
        manifest["encryption"] = {
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": salt_hex,
        }

    # Sign manifest if private key is available
    if priv_file and Path(priv_file).exists():
        seed = load_private_key_seed(Path(priv_file))
        if seed:
            pub_bytes = _ed_publickey(seed)
            manifest["security"]["public_key"] = pub_bytes.hex()
            if not manifest["security"]["developer_id"]:
                manifest["security"]["developer_id"] = author or "author"
            canonical_bytes = get_canonical_json_bytes(manifest)
            signed = sign_data(canonical_bytes, Path(priv_file))
            if signed:
                manifest["security"]["signature"] = signed[0]
                print(f"[*] Manifest cryptographically signed with Ed25519 key (developer_id: {manifest['security']['developer_id']}).")
            else:
                print(f"[!] Warning: Could not sign with private key at {priv_file}.")
        else:
            print(f"[!] Warning: Could not load private key from {priv_file}.")
    else:
        print("[*] No private key provided/found; manifest generated without signature.")

    manifest_file = out_dir / "manifest.json"
    with open(manifest_file, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"[+] Packaging complete! Manifest: {manifest_file} ({len(chunks_meta)} chunks created)")
    return manifest_file


def verify(
    manifest_path: Optional[str] = None,
    chunks_dir: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> bool:
    """Verify chunk inventory, SHA-256 hashes, and Ed25519 author signature."""
    mpath = resolve_manifest_path(manifest_path)
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    with open(mpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    print(f"[*] Verifying package '{manifest.get('package_info', {}).get('name', 'unknown')}'...")
    print(f"[*] Manifest protocol: {manifest.get('protocol')}")

    # 1. Verify Ed25519 signature if present
    sec = manifest.get("security", {})
    signature_hex = sec.get("signature")
    pub_key_hex = sec.get("public_key")

    pub_source = public_key_path or pub_key_hex or (c_dir / "public.pem") or Path("public.pem")

    if signature_hex:
        canonical_bytes = get_canonical_json_bytes(manifest)
        if verify_signature(canonical_bytes, signature_hex, pub_source):
            print(f"[+] Authorship signature VALID (Developer ID: '{sec.get('developer_id')}').")
        else:
            print("[-] Cryptographic signature verification FAILED.")
            return False
    else:
        print("[*] Manifest is unsigned.")

    # 2. Verify chunks inventory and integrity
    chunks = manifest.get("chunks", [])
    if not chunks:
        print("[-] Error: Manifest contains no chunk definitions.")
        return False

    file_hashes: Dict[str, Path] = {}
    for p in c_dir.iterdir():
        if p.is_file() and p.resolve() != mpath.resolve():
            with open(p, "rb") as f:
                h = sha256(f.read()).hexdigest()
                file_hashes[h] = p

    all_valid = True
    missing_chunks = []
    corrupted_chunks = []

    for chunk_info in sorted(chunks, key=lambda x: x["index"]):
        idx = chunk_info["index"]
        expected_hash = chunk_info["sha256"]
        expected_name = chunk_info.get("filename", f"chunk_{idx:03d}.bin")

        cf_path = c_dir / expected_name
        if cf_path.exists():
            with open(cf_path, "rb") as cf:
                actual_hash = sha256(cf.read()).hexdigest()
            if actual_hash == expected_hash:
                continue
            else:
                corrupted_chunks.append((idx, expected_name, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"))
                all_valid = False
                continue

        if expected_hash in file_hashes:
            continue

        missing_chunks.append((idx, expected_name, expected_hash))
        all_valid = False

    if missing_chunks:
        print(f"[-] Missing {len(missing_chunks)} chunk(s):")
        for idx, fname, h in missing_chunks:
            print(f"    - Index {idx} ({fname}): SHA-256 {h}")

    if corrupted_chunks:
        print(f"[-] Corrupted {len(corrupted_chunks)} chunk(s):")
        for idx, fname, reason in corrupted_chunks:
            print(f"    - Index {idx} ({fname}): {reason}")

    if all_valid:
        print(f"[+] All {len(chunks)} chunks verified successfully! Integrity check PASSED.")
        return True
    else:
        print("[-] Chunk verification FAILED.")
        return False


def extract(
    manifest_path: Optional[str] = None,
    chunks_dir: Optional[str] = None,
    output_dir: Optional[str] = None,
    decrypt_key: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> bool:
    """Verify chunks, decrypt (if needed), reassemble, and decompress in one go."""
    mpath = resolve_manifest_path(manifest_path)
    if not mpath.exists():
        print(f"[-] Error: Manifest file {mpath} does not exist.")
        return False

    with open(mpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    c_dir = Path(chunks_dir).resolve() if chunks_dir else mpath.parent

    print("[*] Running pre-flight verification...")
    if not verify(str(mpath), str(c_dir), public_key_path):
        print("[-] Pre-flight verification failed. Aborting extraction.")
        return False

    package_info = manifest.get("package_info", {})
    is_encrypted = package_info.get("encrypted", False)
    source_type = package_info.get("source_type", "file")
    target_name = package_info.get("name", "extracted_output")

    aes_key = None
    if is_encrypted:
        enc_info = manifest.get("encryption", {})
        salt_hex = enc_info.get("salt")
        if not salt_hex:
            print("[-] Error: Package is encrypted but salt is missing from manifest.")
            return False
        salt = bytes.fromhex(salt_hex)

        passphrase = decrypt_key
        if not passphrase:
            prompt_msg = "This package is cryptographically locked. Enter decryption key: "
            try:
                if sys.stdin.isatty():
                    passphrase = getpass.getpass(prompt_msg)
                else:
                    print(prompt_msg, end="", flush=True)
                    passphrase = sys.stdin.readline().strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[-] Decryption aborted by user.")
                return False

        if not passphrase:
            print("[-] Decryption key is required.")
            return False

        aes_key = derive_aes_key(passphrase, salt)

    chunks = sorted(manifest.get("chunks", []), key=lambda x: x["index"])

    hash_to_path: Dict[str, Path] = {}
    for p in c_dir.iterdir():
        if p.is_file() and p.resolve() != mpath.resolve():
            with open(p, "rb") as f:
                h = sha256(f.read()).hexdigest()
                hash_to_path[h] = p

    out_base = Path(output_dir).resolve() if output_dir else Path.cwd()
    out_base.mkdir(parents=True, exist_ok=True)

    temp_reassembled = out_base / f".tmp_{target_name}.archive"
    print(f"[*] Reassembling {len(chunks)} chunks...")

    try:
        with open(temp_reassembled, "wb") as out_f:
            for chunk_info in chunks:
                idx = chunk_info["index"]
                expected_hash = chunk_info["sha256"]
                expected_name = chunk_info.get("filename")

                cf_path = c_dir / expected_name if expected_name else None
                if not (cf_path and cf_path.exists() and sha256(cf_path.read_bytes()).hexdigest() == expected_hash):
                    cf_path = hash_to_path.get(expected_hash)

                if not cf_path or not cf_path.exists():
                    print(f"[-] Could not find chunk file for index {idx} (hash {expected_hash})")
                    return False

                with open(cf_path, "rb") as cf:
                    raw_chunk = cf.read()

                if is_encrypted:
                    if len(raw_chunk) < (NONCE_SIZE + TAG_SIZE):
                        print(f"[-] Corrupt encrypted chunk {idx}: file too small")
                        return False
                    nonce = raw_chunk[:NONCE_SIZE]
                    ciphertext_with_tag = raw_chunk[NONCE_SIZE:]
                    try:
                        decrypted_data = decrypt_aes_gcm(
                            aes_key,
                            nonce,
                            ciphertext_with_tag,
                            aad=idx.to_bytes(4, "big"),
                        )
                    except Exception:
                        print("[-] Cryptographic authentication layer rejected decryption key or corrupted data.")
                        return False
                    out_f.write(decrypted_data)
                else:
                    out_f.write(raw_chunk)

        print(f"[*] Decompressing and reconstructing '{target_name}' (type: {source_type})...")
        destination_path = out_base / target_name

        if source_type == "file":
            with gzip.open(temp_reassembled, "rb") as gz_in, open(destination_path, "wb") as f_out:
                shutil.copyfileobj(gz_in, f_out)
        elif source_type == "directory":
            with tarfile.open(temp_reassembled, "r:gz") as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=out_base, filter="data")
                else:
                    tar.extractall(path=out_base)
        else:
            print(f"[-] Unknown source_type '{source_type}'.")
            return False

        print(f"[+] Reassembly and extraction complete -> {destination_path}")
        return True

    finally:
        if temp_reassembled.exists():
            temp_reassembled.unlink()


# ==============================================================================
# CLI Entry Point & Parameter Parsing
# ==============================================================================

def main(custom_argv: Optional[List[str]] = None):
    raw_argv = list(sys.argv[1:]) if custom_argv is None else list(custom_argv)
    prog_name = Path(sys.argv[0]).name

    # Check if invoked via script name ending in 'keygen' (e.g. core.pykeygen, b2chks.pykeygen)
    if "keygen" in prog_name and ("keygen" not in raw_argv) and ("-h" not in raw_argv) and ("--help" not in raw_argv):
        raw_argv.insert(0, "keygen")

    parser = argparse.ArgumentParser(
        prog="b2chks",
        description="B2CHKS: High-performance file packaging, chunking, compression, and distribution tool.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Keygen subcommand
    for sub in ["keygen", "key-gen", "genkey"]:
        parser_keygen = subparsers.add_parser(sub, help="Generate Ed25519 signing keypair")
        parser_keygen.add_argument("--author", "-a", type=str, default="author", help="Author/developer identifier")
        parser_keygen.add_argument("--out-dir", "-o", type=str, default=".", help="Output directory for keys")

    # Pack subcommand
    for name in ["pack", "package", "compress"]:
        parser_pack = subparsers.add_parser(name, help="Compress, chunk, encrypt and sign a file or directory")
        parser_pack.add_argument("source", type=str, help="Path to file or directory to pack")
        parser_pack.add_argument(
            "--chunk-size", "--chunk_size", "-c", "--size",
            dest="chunk_size",
            type=str,
            required=True,
            help="Size of each chunk (e.g. 100m, 500m, 1g, 500k). Required.",
        )
        parser_pack.add_argument("--encrypt-key", "--encrypt_key", "-e", dest="encrypt_key", type=str, default=None, help="Passphrase to encrypt chunks with AES-256-GCM")
        parser_pack.add_argument("--private-key", "--private_key", "-k", "--key", dest="private_key", type=str, default=None, help="Path to Ed25519 private.pem to sign manifest")
        parser_pack.add_argument("--author", "-a", type=str, default=None, help="Author/Developer ID for manifest")
        parser_pack.add_argument("--output-dir", "--output_dir", "-o", dest="output_dir", type=str, default=None, help="Output directory for chunks and manifest (defaults to current dir)")
        parser_pack.add_argument("--keygen", "--generate-key", dest="generate_key", action="store_true", help="Automatically generate keypair if none exists and sign package")

    # Verify subcommand
    for name in ["verify", "check"]:
        parser_verify = subparsers.add_parser(name, help="Verify chunk integrity and author signature")
        parser_verify.add_argument("manifest", type=str, nargs="?", default=None, help="Path to manifest.json or directory containing it")
        parser_verify.add_argument("--chunks-dir", "--chunks_dir", "-d", dest="chunks_dir", type=str, default=None, help="Directory containing chunk files")
        parser_verify.add_argument("--public-key", "--public_key", "-k", dest="public_key", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")

    # Extract subcommand
    for name in ["extract", "unpack", "decompress"]:
        parser_extract = subparsers.add_parser(name, help="Verify, decrypt, assemble, and decompress package")
        parser_extract.add_argument("manifest", type=str, nargs="?", default=None, help="Path to manifest.json or directory containing it")
        parser_extract.add_argument("--chunks-dir", "--chunks_dir", "-d", dest="chunks_dir", type=str, default=None, help="Directory containing chunk files")
        parser_extract.add_argument("--output-dir", "--output_dir", "-o", dest="output_dir", type=str, default=None, help="Destination directory for extracted files")
        parser_extract.add_argument("--decrypt-key", "--decrypt_key", "-e", dest="decrypt_key", type=str, default=None, help="Decryption key passphrase (prompts if omitted and encrypted)")
        parser_extract.add_argument("--public-key", "--public_key", "-k", dest="public_key", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")

    args = parser.parse_args(raw_argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command in ["keygen", "key-gen", "genkey"]:
            priv, pub = generate_keypair(args.author, args.out_dir)
            print(f"[+] Generated Ed25519 keypair for author '{args.author}':")
            print(f"    Private key: {priv}")
            print(f"    Public key:  {pub}")

        elif args.command in ["pack", "package", "compress"]:
            pack(
                source=args.source,
                chunk_size_str=args.chunk_size,
                output_dir=args.output_dir,
                encrypt_key=args.encrypt_key,
                private_key_path=args.private_key,
                author=args.author,
                generate_key=args.generate_key,
            )

        elif args.command in ["verify", "check"]:
            ok = verify(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                public_key_path=args.public_key,
            )
            if not ok:
                sys.exit(1)

        elif args.command in ["extract", "unpack", "decompress"]:
            ok = extract(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                output_dir=args.output_dir,
                decrypt_key=args.decrypt_key,
                public_key_path=args.public_key,
            )
            if not ok:
                sys.exit(1)

    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
