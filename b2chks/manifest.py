"""Manifest schema validation, canonical JSON serialization, and versioning."""
import json
from pathlib import Path
from typing import Dict, Any, Union, Optional

from b2chks.exceptions import ManifestError

PROTOCOL_VERSIONS = ["b2chks", "b2chks-v1", "chunk-core-v1"]

def get_canonical_json_bytes(manifest_dict: Dict[str, Any]) -> bytes:
    """Produce deterministic canonical JSON bytes excluding the signature field."""
    clean = json.loads(json.dumps(manifest_dict))
    if "security" in clean and "signature" in clean["security"]:
        del clean["security"]["signature"]
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")

def validate_manifest_schema(data: Dict[str, Any]) -> None:
    """Validate that manifest contains required fields and correct types."""
    if not isinstance(data, dict):
        raise ManifestError("Manifest root must be a JSON object")

    protocol = data.get("protocol")
    if not protocol or not any(protocol.startswith(v) for v in ["b2chks", "chunk-core"]):
        raise ManifestError(f"Unsupported protocol identifier: '{protocol}'")

    if "package_info" not in data or not isinstance(data["package_info"], dict):
        raise ManifestError("Missing or invalid 'package_info' in manifest")

    pkg = data["package_info"]
    for field in ["name", "source_type", "total_size_bytes", "chunk_size_bytes", "total_chunks"]:
        if field not in pkg:
            raise ManifestError(f"Missing required package_info field: '{field}'")

    if pkg["source_type"] not in ["file", "directory"]:
        raise ManifestError(f"Invalid source_type: '{pkg['source_type']}'")

    if not isinstance(data.get("chunks"), list) or not data["chunks"]:
        raise ManifestError("Manifest must contain a non-empty 'chunks' list")

    for i, chunk in enumerate(data["chunks"]):
        if not isinstance(chunk, dict):
            raise ManifestError(f"Chunk at index {i} is not a valid object")
        for req in ["index", "filename", "size", "sha256"]:
            if req not in chunk:
                raise ManifestError(f"Chunk {i} is missing required field '{req}'")

def load_manifest(path: Union[str, Path]) -> Dict[str, Any]:
    """Read, parse, and validate manifest from disk."""
    m_path = Path(path).resolve()
    if not m_path.exists():
        raise FileNotFoundError(f"Manifest file not found: {m_path}")

    try:
        with open(m_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ManifestError(f"Failed to parse manifest JSON: {e}") from e

    validate_manifest_schema(data)
    return data

def write_manifest(manifest_dict: Dict[str, Any], path: Union[str, Path]) -> None:
    """Validate and write formatted manifest JSON to disk."""
    validate_manifest_schema(manifest_dict)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest_dict, f, indent=2)
