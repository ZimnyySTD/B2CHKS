from b2chks import B2CHKS


def test_zip_uses_strong_lossless_compression(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes((b"repeated-data-" * 10000))

    archive = B2CHKS.pack(source=source, output_dir=tmp_path / "zip", compression_level=9)
    extracted = tmp_path / "extracted"
    assert B2CHKS.extract(archive, output_dir=extracted)
    assert (extracted / source.name).read_bytes() == source.read_bytes()


def test_zstd_level_is_lossless(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes((b"repeated-data-" * 10000))

    manifest = B2CHKS.pack(
        source=source,
        chunk_size="16k",
        output_dir=tmp_path / "b2chks",
        compression_level=9,
    )
    extracted = tmp_path / "extracted-zstd"
    assert B2CHKS.extract(manifest, output_dir=extracted)
    assert (extracted / source.name).read_bytes() == source.read_bytes()
