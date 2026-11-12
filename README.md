# B2CHKS — Native-Performance File Packaging & Compression Protocol

[![Tests](https://img.shields.io/badge/tests-32%20passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)]()
[![Native Performance](https://img.shields.io/badge/architecture-native%20cryptography-brightgreen.svg)]()

**B2CHKS** is a modern, high-performance file packaging, chunking, compression, and cryptographically secure distribution protocol designed to replace legacy archive formats with a decoupled, high-throughput architecture.

Separating **packaging** from **hosting**, B2CHKS allows you to compress, optionally chunk, optionally encrypt (AES-256-GCM with memory-hard `scrypt`), and cryptographically sign (Ed25519) any file or directory into lightweight chunks and a portable `manifest.json`.

---

## Clean Command Overview

B2CHKS provides 5 clean, straightforward commands:
- `b2chks pack`: Create a standard ZIP, or compress/chunk (or `--nochunks`) with Zstandard, encryption, and signing.
- `b2chks extract`: Verify, decrypt, and decompress package in one go.
- `b2chks verify`: Verify package integrity and author signature.
- `b2chks keygen`: Generate Ed25519 author signing keys.
- `b2chks uninstall`: Cleanly remove B2CHKS from the system.

---

## Quick Start

### 1. Global Installation
```bash
python install.py
```
*Note: If an installation already exists, `install.py` replaces and refreshes it cleanly.*

### 2. Standard ZIP archive
With neither `--chunk-size` nor `--nochunks`, B2CHKS creates a normal ZIP archive
with no manifest or chunk files:
```bash
b2chks pack ./my_project
```

### 3. B2CHKS packaging without chunking (`--nochunks`)
To compress a file or directory into a single package without splitting into multiple chunks:
```bash
b2chks pack ./my_project --nochunks
```

### 4. Packaging with Chunking
```bash
# Split into 100MB chunks
b2chks pack ./my_game_folder --chunk-size 100m

# Split with AES-256-GCM encryption + scrypt
b2chks pack ./my_game_folder --chunk-size 100m --encrypt-key "MySecretPassphrase123"
```

### 5. Verify Chunks & Signature
```bash
b2chks verify manifest.json --public-key public.pem
```

### 6. Extract in One Go
```bash
# Standard ZIP or B2CHKS package
b2chks extract manifest.json --output-dir ./extracted
b2chks extract my_project.zip --output-dir ./extracted

# Encrypted package (interactive password prompt)
b2chks extract manifest.json
```

---

## Detailed Documentation & Guides

- 👉 **[INSTRUCTIONS.md](INSTRUCTIONS.md)**: Comprehensive CLI reference flags, installation guides, and application integration examples.
- 👉 **[PROTOCOL.md](PROTOCOL.md)**: Formal protocol specifications, manifest schema, and cryptographic security properties.

---

## Python SDK / Application Embedding

B2CHKS provides a clean, decoupled SDK for integration into game launchers, backup tools, and deployment pipelines:

```python
from b2chks import B2CHKS

# Standard ZIP when no chunk options are supplied
manifest = B2CHKS.pack(
    source="./project_files",
)

# Extract
B2CHKS.extract(
    manifest=manifest,
    output_dir="./restored",
    decrypt_key="SecretPassword",
)
```

---

## Running Tests & Benchmarks

Run the test suite:
```bash
pytest -v
```

Run benchmarks:
```bash
python benchmarks/benchmark_suite.py
```

## Performance and security options

B2CHKS uses a streaming pack/extract pipeline and bounded chunk reads to avoid
the old full temporary-archive pass. The CLI also provides low-overhead
progress output, automatically disabled when output is redirected:

```bash
b2chks extract manifest.json --trusted-public-key public.pem
b2chks extract manifest.json --no-progress
b2chks extract manifest.json --json
```

Optional extraction limits are available for untrusted packages without
changing the default behavior:

```bash
b2chks extract manifest.json \
  --max-output-size 100000000000 \
  --max-files 100000 \
  --max-file-size 10000000000 \
  --max-compression-ratio 500
```

Use `--trusted-public-key` when the manifest signature must match a key
obtained from a trusted source; the key embedded in a manifest is otherwise
only an identity claim.

---

## License & Protocol
©B2CHKS
