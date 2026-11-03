"""Benchmark extraction speed."""
import os
import tempfile
import time
from b2chks import B2CHKS

def run_benchmark():
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "bench.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(10 * 1024 * 1024))
        dist = os.path.join(td, "dist")
        ext = os.path.join(td, "ext")
        m = B2CHKS.pack(src, chunk_size="1m", output_dir=dist, encrypt_key="BenchSecret")

        t0 = time.time()
        B2CHKS.extract(m, output_dir=ext, decrypt_key="BenchSecret")
        elapsed = time.time() - t0
        mb_per_sec = 10.0 / elapsed
        print(f"[EXTRACT BENCHMARK] 10MB encrypted extracted in {elapsed:.2f}s ({mb_per_sec:.2f} MB/s)")

if __name__ == "__main__":
    run_benchmark()
