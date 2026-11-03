"""Tests for protocol compatibility and cross-version handling."""
import pytest
from b2chks.manifest import validate_manifest_schema

def test_chunkcore_legacy_manifest_compatibility():
    legacy_manifest = {
        "protocol": "chunk-core-v1",
        "package_info": {
            "name": "LegacyBuild.iso",
            "source_type": "file",
            "total_size_bytes": 1048576,
            "chunk_size_bytes": 524288,
            "total_chunks": 2,
            "encrypted": False,
        },
        "chunks": [
            {"index": 0, "filename": "chunk_000.bin", "size": 524288, "sha256": "h1"},
            {"index": 1, "filename": "chunk_001.bin", "size": 524288, "sha256": "h2"},
        ],
    }
    # Should validate without throwing ManifestError
    validate_manifest_schema(legacy_manifest)
