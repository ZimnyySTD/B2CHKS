"""Tests for manifest schema validation and error handling."""
import json
import pytest
from b2chks.exceptions import ManifestError
from b2chks.manifest import validate_manifest_schema

def test_manifest_validation_valid():
    valid_manifest = {
        "protocol": "b2chks",
        "package_info": {
            "name": "archive.bin",
            "source_type": "file",
            "total_size_bytes": 1000,
            "chunk_size_bytes": 500,
            "total_chunks": 2,
            "encrypted": False,
        },
        "chunks": [
            {"index": 0, "filename": "chunk_000.bin", "size": 500, "sha256": "abc"},
            {"index": 1, "filename": "chunk_001.bin", "size": 500, "sha256": "def"},
        ],
    }
    validate_manifest_schema(valid_manifest)

def test_manifest_validation_invalid_protocol():
    invalid = {"protocol": "unknown-protocol"}
    with pytest.raises(ManifestError):
        validate_manifest_schema(invalid)

def test_manifest_validation_missing_chunks():
    invalid = {
        "protocol": "b2chks",
        "package_info": {
            "name": "a",
            "source_type": "file",
            "total_size_bytes": 10,
            "chunk_size_bytes": 10,
            "total_chunks": 1,
        },
        "chunks": [],
    }
    with pytest.raises(ManifestError):
        validate_manifest_schema(invalid)
