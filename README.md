# B2CHKS — High-Performance File Packaging & Compression Protocol

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20optional-brightgreen.svg)]()

**B2CHKS** is a modern, cross-platform file packaging, chunking, compression, and cryptographically secure distribution protocol designed to replace legacy archive formats (like `.rar` or `.7z` split volumes) with a decoupled, high-performance architecture.

Separating **packaging** from **hosting**, B2CHKS allows you to compress, split, optionally encrypt (AES-256-GCM with memory-hard `scrypt`), and cryptographically sign (Ed25519) any file or directory into lightweight chunks and a portable `manifest.json`.

---

## Key Features

- **Automatic Stream Compression**: Fast, high-throughput DEFLATE compression (`gzip` for single files, `tar.gz` for directories) before chunking.
- **Dynamic Chunking**: Enforced, strict user-defined chunk size boundaries (`500k`, `100m`, `1g`, `2gb`).
- **Anti-Brute-Force Encryption**: AES-256-GCM payload encryption with memory-hard `scrypt` key derivation (protecting passphrases against GPU/ASIC cracking).
- **Authorship Verification**: Asymmetric Ed25519 author signing and verification over deterministic canonical JSON manifests.
- **Zero-Dependency Core**: Built-in pure-Python RFC 8032 Ed25519 and NIST SP 800-38D AES-GCM engine; runs out of the box with standard Python 3.8+ on any OS.
- **Hardware Acceleration**: Automatically detects and leverages `cryptography` C-extensions / AES-NI instructions when available.
- **Multi-Threaded Pipeline**: High-throughput parallel encryption, hashing, and decryption across all CPU cores.
- **Embeddable Python SDK**: Clean `B2CHKS` class with progress callbacks (`progress_callback`) for GUI applications, web services, and scripts.
- **Global Installation**: Single-command global setup for Windows (PowerShell & CMD), macOS, and Linux.

---

## Quick Start

### 1. Global Installation
To install `b2chks` and `core` commands globally on your machine:
```bash
python install.py
```
Or via pip:
```bash
pip install -e .
```

### 2. Generate Author Keys
```bash
b2chks keygen --author "arcxan"
```
Produces `private.pem` (kept secret by the developer) and `public.pem` (shared publicly).

### 3. Pack a File or Directory
```bash
# Packaging with automatic compression and chunking
b2chks pack ./my_game_folder --chunk-size 500m

# Packaging with AES-256-GCM encryption + scrypt
b2chks pack ./my_game_folder --chunk-size 500m --encrypt-key "MySecretPassphrase123"
```

### 4. Verify Chunks & Signature
```bash
b2chks verify manifest.json --public-key public.pem
```

### 5. Extract & Reassemble in One Go
```bash
# Unencrypted package
b2chks extract manifest.json --output-dir ./extracted

# Encrypted package (interactive password prompt)
b2chks extract manifest.json
```

---

## Detailed Documentation & Guides

For comprehensive usage guides, CLI reference flags, protocol specifications, and application integration examples, see:

👉 **[INSTRUCTIONS.md](INSTRUCTIONS.md)**

---

## Python SDK / Application Embedding

B2CHKS can be embedded directly in your Python applications and GUI tools:

```python
import b2chks
from b2chks import B2CHKS

# Pack with progress updates (ideal for GUI progress bars)
manifest = B2CHKS.pack(
    source="./project_files",
    chunk_size="100m",
    encrypt_key="SecretPassword",
    progress_callback=lambda cur, tot, stage: print(f"[{stage}] {cur}/{tot}")
)

# Extract
B2CHKS.extract(
    manifest=manifest,
    output_dir="./restored",
    decrypt_key="SecretPassword",
)
```

---

## Running Tests

Run the full test suite with pytest:
```bash
pytest -v
```

---

## License & Protocol
ChunkCore / B2CHKS Protocol v1.
