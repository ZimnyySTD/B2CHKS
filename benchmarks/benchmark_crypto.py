"""Benchmark raw cryptographic throughput."""
import os
import time
from b2chks.encryption import encrypt_aes_gcm, decrypt_aes_gcm

def run_benchmark():
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = os.urandom(10 * 1024 * 1024)  # 10MB
    aad = b"benchmark"

    t0 = time.time()
    ct = encrypt_aes_gcm(key, nonce, data, aad=aad)
    t_enc = time.time() - t0

    t1 = time.time()
    pt = decrypt_aes_gcm(key, nonce, ct, aad=aad)
    t_dec = time.time() - t1

    assert pt == data
    print(f"[CRYPTO BENCHMARK] 10MB AES-GCM Encrypted: {10.0 / t_enc:.2f} MB/s | Decrypted: {10.0 / t_dec:.2f} MB/s")

if __name__ == "__main__":
    run_benchmark()
