from b2chks import B2CHKS


def test_default_pack_creates_standard_zip(tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "readme.txt").write_text("plain zip archive")

    archive = B2CHKS.pack(source=source, output_dir=tmp_path / "dist")

    assert archive.name == "project.zip"
    assert archive.exists()
    assert not (archive.parent / "manifest.json").exists()
    assert not list(archive.parent.glob("*.bin"))

    extracted = tmp_path / "extracted"
    assert B2CHKS.extract(manifest=archive, output_dir=extracted)
    assert (extracted / "project" / "readme.txt").read_text() == "plain zip archive"
