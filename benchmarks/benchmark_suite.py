"""Comprehensive benchmark suite measuring throughput, memory, and compression ratios."""
import os
import tempfile
import time
import tracemalloc
from b2chks import B2CHKS
import b2chks

def run_suite():
    print("=" * 70)
    print("          B2CHKS Comprehensive Performance Benchmarks")
    print("=" * 70)

    scenarios = [
        ("Small File (64KB)", 64 * 1024, "16k", "gzip"),
        ("Medium File (5MB)", 5 * 1024 * 1024, "512k", "gzip"),
        ("Large File (20MB)", 20 * 1024 * 1024, "1m", "gzip"),
        ("Zstandard (5MB)", 5 * 1024 * 1024, "512k", "zstd"),
    ]

    for label, size, chunk_sz, comp in scenarios:
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "source.bin")
            with open(src, "wb") as f:
                f.write(os.urandom(size))

            dist = os.path.join(td, "dist")
            ext = os.path.join(td, "ext")

            # 1. Benchmark Packaging
            tracemalloc.start()
            t0 = time.time()
            m = B2CHKS.pack(src, chunk_size=chunk_sz, output_dir=dist, encrypt_key="Passphrase123", compression=comp)
            pack_time = time.time() - t0
            peak_pack_mem = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
            tracemalloc.stop()

            # 2. Benchmark Extraction
            tracemalloc.start()
            t1 = time.time()
            ok = B2CHKS.extract(m, output_dir=ext, decrypt_key="Passphrase123")
            ext_time = time.time() - t1
            peak_ext_mem = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
            tracemalloc.stop()

            mb = size / (1024 * 1024)
            pack_speed = mb / pack_time
            ext_speed = mb / ext_time

            print(f"[*] {label}:")
            print(f"    - Pack Speed:    {pack_speed:.2f} MB/s (Time: {pack_time:.3f}s, Peak RAM: {peak_pack_mem:.2f} MB)")
            print(f"    - Extract Speed: {ext_speed:.2f} MB/s (Time: {ext_time:.3f}s, Peak RAM: {peak_ext_mem:.2f} MB)")

    print("=" * 70)

if __name__ == "__main__":
    run_suite()
