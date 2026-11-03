"""Tests for cryptographic backends and algorithms."""
import os
from pathlib import Path
import pytest
from b2chks.encryption import derive_aes_key, encrypt_aes_gcm, decrypt_aes_gcm, DecryptionError
from b2chks.signing import generate_keypair, sign_data, verify_signature

def test_aes_gcm_aad_integrity():
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = b"Secret payload data"
    aad = (0).to_bytes(4, "big")

    ct = encrypt_aes_gcm(key, nonce, data, aad=aad)
    pt = decrypt_aes_gcm(key, nonce, ct, aad=aad)
    assert pt == data

    # Wrong AAD (chunk reordering attack) must raise DecryptionError
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
