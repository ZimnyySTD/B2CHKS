"""Native-only Ed25519 signing and verification with cryptography."""
import base64
from pathlib import Path
from typing import Optional, Tuple, Any

from b2chks.backends import HAVE_CRYPTOGRAPHY, require_cryptography

if HAVE_CRYPTOGRAPHY:
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519


def _parse_pem(pem_str: str) -> bytes:
    clean_lines = []
    for line in pem_str.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("-----"):
            continue
        clean_lines.append(line)
    return base64.b64decode("".join(clean_lines))


def generate_keypair(author: str = "author", out_dir: str = ".") -> Tuple[str, str]:
    """Generate Ed25519 keypair and save to private.pem and public.pem using native cryptography."""
    require_cryptography()
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    priv_file = out_path / "private.pem"
    pub_file = out_path / "public.pem"

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

    return str(priv_file), str(pub_file)


def load_private_key(priv_path: Path):
    """Load native Ed25519PrivateKey from PEM or raw seed bytes."""
    require_cryptography()
    content = priv_path.read_bytes()
    if b"BEGIN" in content:
        return crypto_serialization.load_pem_private_key(content, password=None)
    elif len(content) == 32:
        return crypto_ed25519.Ed25519PrivateKey.from_private_bytes(content)
    raise ValueError(f"Invalid private key format at {priv_path}")


def load_public_key(pub_source: Any):
    """Load native Ed25519PublicKey from PEM file, hex string, or raw bytes."""
    require_cryptography()
    if isinstance(pub_source, (str, Path)) and Path(pub_source).exists():
        content = Path(pub_source).read_bytes()
        if b"BEGIN" in content:
            return crypto_serialization.load_pem_public_key(content)
        elif len(content) == 32:
            return crypto_ed25519.Ed25519PublicKey.from_public_bytes(content)
    if isinstance(pub_source, str):
        clean = pub_source.strip()
        if len(clean) == 64:
            return crypto_ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(clean))
        if "BEGIN" in clean:
            return crypto_serialization.load_pem_public_key(clean.encode())
    if isinstance(pub_source, bytes) and len(pub_source) == 32:
        return crypto_ed25519.Ed25519PublicKey.from_public_bytes(pub_source)
    raise ValueError("Invalid public key source")


def sign_data(data: bytes, priv_path: Path) -> Optional[Tuple[str, str]]:
    """Sign data using native Ed25519. Returns (signature_hex, public_key_hex)."""
    require_cryptography()
    try:
        priv_obj = load_private_key(priv_path)
        sig_bytes = priv_obj.sign(data)
        pub_obj = priv_obj.public_key()
        pub_bytes = pub_obj.public_bytes(
            encoding=crypto_serialization.Encoding.Raw,
            format=crypto_serialization.PublicFormat.Raw,
        )
        return sig_bytes.hex(), pub_bytes.hex()
    except Exception:
        return None


def verify_signature(data: bytes, signature_hex: str, pub_source: Any) -> bool:
    """Verify Ed25519 signature using native cryptography."""
    require_cryptography()
    try:
        pub_obj = load_public_key(pub_source)
        sig = bytes.fromhex(signature_hex)
        pub_obj.verify(sig, data)
        return True
    except Exception:
        return False
