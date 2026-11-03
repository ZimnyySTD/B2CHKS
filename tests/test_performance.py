"""Tests for high-throughput performance pipelines."""
import os
import time
from b2chks import B2CHKS

def test_performance_pack_and_extract_speed(tmp_path):
    # 2MB file
    src = tmp_path / "speed_test.bin"
    src.write_bytes(os.urandom(2 * 1024 * 1024))
    dist = tmp_path / "dist"
    ext = tmp_path / "ext"

    t0 = time.time()
    manifest = B2CHKS.pack(
        source=src,
        chunk_size="256k",
        output_dir=dist,
        encrypt_key="SpeedyKey123",
        workers=4,
    )
    t_pack = time.time() - t0

    t1 = time.time()
    ok = B2CHKS.extract(
        manifest=manifest,
        output_dir=ext,
        decrypt_key="SpeedyKey123",
        workers=4,
    )
    t_extract = time.time() - t1

    assert ok
    assert t_pack < 10.0  # Must be fast
    assert t_extract < 10.0
