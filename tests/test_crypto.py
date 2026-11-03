"""Tests for cryptographic backends, test vectors, and native dependency checks."""
import os
from pathlib import Path
import pytest
from b2chks.encryption import derive_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from b2chks.exceptions import DecryptionError, MissingDependencyError
from b2chks.signing import generate_keypair, sign_data, verify_signature
import b2chks.backends as backends

def test_aes_gcm_aad_integrity():
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = b"Secret payload data"
    aad = (0).to_bytes(4, "big")

    ct = encrypt_aes_gcm(key, nonce, data, aad=aad)
    pt = decrypt_aes_gcm(key, nonce, ct, aad=aad)
    assert pt == data

    # Wrong AAD must raise DecryptionError
    wrong_aad = (1).to_bytes(4, "big")
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(key, nonce, ct, aad=wrong_aad)

    # Tampered ciphertext must fail
    tampered = ct[:-5] + b"\x00" + ct[-4:]
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(key, nonce, tampered, aad=aad)

def test_ed25519_sign_verify(tmp_path):
    priv, pub = generate_keypair(author="crypto_tester", out_dir=str(tmp_path))
    message = b"Manifest canonical message"

    sig, pub_hex = sign_data(message, Path(priv))
    assert verify_signature(message, sig, pub_hex)
    assert verify_signature(message, sig, Path(pub))
    assert not verify_signature(b"tampered message", sig, Path(pub))

def test_rfc8032_ed25519_vector():
    # RFC 8032 Test Vector 1 for Ed25519
    # Secret key seed (32 bytes)
    sk_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    msg = b""
    expected_sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

    sk_bytes = bytes.fromhex(sk_hex)
    from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed25519
    priv_key = crypto_ed25519.Ed25519PrivateKey.from_private_bytes(sk_bytes)
    sig = priv_key.sign(msg)
    assert sig.hex() == expected_sig_hex

    # Verification
    pub_key = crypto_ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
    pub_key.verify(sig, msg)

def test_nist_aes_gcm_test_vector():
    # NIST SP 800-38D Test Case 14 (AES-256-GCM)
    key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    nonce = bytes.fromhex("000000000000000000000000")
    plaintext = bytes.fromhex("00000000000000000000000000000000")
    expected_ciphertext = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
    expected_tag = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")

    ct_with_tag = encrypt_aes_gcm(key, nonce, plaintext, aad=b"")
    assert ct_with_tag == (expected_ciphertext + expected_tag)

    pt = decrypt_aes_gcm(key, nonce, ct_with_tag, aad=b"")
    assert pt == plaintext

def test_missing_dependency_error(monkeypatch):
    monkeypatch.setattr(backends, "HAVE_CRYPTOGRAPHY", False)
    with pytest.raises(MissingDependencyError) as exc_info:
        backends.require_cryptography()
    assert "cryptography" in str(exc_info.value)
