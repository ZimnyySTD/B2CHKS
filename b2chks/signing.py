"""Ed25519 signing and verification with native cryptography and pure-Python fallback."""
import base64
import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple, Any

from b2chks.backends import HAVE_CRYPTOGRAPHY

if HAVE_CRYPTOGRAPHY:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519

# RFC 8032 pure-Python implementation
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

def _ed_edwards(P, Q):
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _ed_inv(1 + _ED_D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _ed_inv(1 - _ED_D * x1 * x2 * y1 * y2)
    return [x3 % _ED_Q, y3 % _ED_Q]

def _ed_scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _ed_scalarmult(P, e // 2)
    Q = _ed_edwards(Q, Q)
    if e & 1:
        Q = _ed_edwards(Q, P)
    return Q

def _ed_encodeint(y: int) -> bytes:
    return int(y).to_bytes(32, "little")

def _ed_encodepoint(P) -> bytes:
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

def _ed_isoncurve(P) -> bool:
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_Q == 0

def _ed_decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")

def _ed_decodepoint(s: bytes):
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
    """Sign data using Ed25519. Returns (signature_hex, public_key_hex)."""
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
