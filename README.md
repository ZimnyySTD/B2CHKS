# B2CHKS — Native-Performance File Packaging & Compression Protocol

[![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)]()
[![Native Performance](https://img.shields.io/badge/architecture-native%20cryptography-brightgreen.svg)]()

**B2CHKS** is a modern, high-performance file packaging, chunking, compression, and cryptographically secure distribution protocol designed to replace legacy archive formats (such as `.rar` or `.7z` split volumes) with a decoupled, high-performance architecture.

Separating **packaging** from **hosting**, B2CHKS allows you to compress, split, optionally encrypt (AES-256-GCM with memory-hard `scrypt`), and cryptographically sign (Ed25519) any file or directory into lightweight chunks and a portable `manifest.json`.

---

## Native Performance Architecture

B2CHKS enforces high-performance native-backed operations:
- **AES-256-GCM Encryption**: Powered by OpenSSL / native C-extensions via `cryptography` (AES-NI accelerated).
- **Ed25519 Author Signatures**: High-speed native Edwards curve asymmetric signing and verification via `cryptography`.
- **Anti-Brute-Force Key Derivation**: Native `hashlib.scrypt` (memory-hard, resistant to GPU/ASIC cracking).
- **Chunk Hashing**: Streaming native `hashlib.sha256()`.
- **Stream Compression**: High-throughput DEFLATE via native `zlib`, with optional Zstandard (`zstd`) support.
- **Bounded Streaming Pipeline**: Memory-efficient bounded worker queues (`ThreadPoolExecutor`) and 4MB streaming buffers prevent excessive RAM allocation during large file processing.

---

## Quick Start

### 1. Global Installation
To install `b2chks` and `core` commands globally on your machine:
```bash
python install.py
```
*Note: Running `install.py` when an installation already exists automatically replaces and refreshes it cleanly.*

### 2. Uninstallation
To uninstall B2CHKS globally (only if currently installed):
```bash
python uninstall.py
# or
b2chks uninstall
```

### 3. Generate Author Keys
```bash
b2chks keygen --author "arcxan"
```
Produces `private.pem` (kept secret by the developer) and `public.pem` (shared publicly).

### 4. Pack a File or Directory
```bash
# Packaging with automatic compression and chunking
b2chks pack ./my_game_folder --chunk-size 500m

# Packaging with AES-256-GCM encryption + scrypt anti-brute-force
b2chks pack ./my_game_folder --chunk-size 500m --encrypt-key "MySecretPassphrase123"

# Packaging with high-speed Zstandard compression
b2chks pack ./my_game_folder --chunk-size 500m --compression zstd
```

### 5. Verify Chunks & Signature (Multi-Threaded)
```bash
b2chks verify manifest.json --public-key public.pem
```

### 6. Extract & Reassemble in One Go
```bash
# Unencrypted package
b2chks extract manifest.json --output-dir ./extracted

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

# Pack with progress updates (ideal for GUI progress bars)
manifest = B2CHKS.pack(
    source="./project_files",
    chunk_size="100m",
    encrypt_key="SecretPassword",
    compression="gzip", # or "zstd"
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

## Running Tests & Benchmarks

Run the full test suite with pytest:
```bash
pytest -v
```

Run performance benchmarks:
```bash
python benchmarks/benchmark_suite.py
```

---

## License & Protocol
ChunkCore / B2CHKS Protocol v1.
