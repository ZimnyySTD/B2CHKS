# B2CHKS Protocol Instructions & Developer Guide

**B2CHKS** is a cross-platform, high-performance file packaging, chunking, compression, and secure distribution protocol, CLI tool, and embeddable Python SDK. It decouples packaging from hosting, allowing creators to compress, split, optionally encrypt (AES-256-GCM with anti-brute-force scrypt), and cryptographically sign (Ed25519) any file or directory into lightweight chunks and a JSON manifest.

---

## 1. Quick Global Installation

Install B2CHKS globally so that `b2chks` and `core` commands are available anywhere in your terminal or command prompt:

### Automated Global Install (Linux, macOS, Windows)
```bash
python install.py
```
This automatically configures global CLI launchers in your system PATH (`b2chks` and `core`).

### Or install via pip:
```bash
pip install -e .
```

---

## 2. CLI Overview & Commands

B2CHKS provides the following primary subcommands:
1. `keygen` (aliases: `key-gen`, `genkey`): Generate an Ed25519 keypair for author signing and verification.
2. `pack` (aliases: `package`, `compress`): Compress, chunk, optionally encrypt, and sign a file or directory.
3. `verify` (alias: `check`): Inspect chunk inventory, verify SHA-256 chunk hashes, and validate manifest authorship signature.
4. `extract` (aliases: `unpack`, `decompress`): Verify, decrypt (if encrypted), reassemble, and decompress the package in one go.

Run `b2chks --help` or `python core.py <subcommand> --help` to see detailed options.

---

## 3. Step-by-Step Usage Guide

### Step A: Generating Developer Signing Keys

To generate signing keys proving authorship:
```bash
python core.pykeygen --author "arcxan"
# or
b2chks keygen --author "arcxan" --out-dir ./keys
```
- Outputs:
  - `private.pem`: Private signing key.
  - `public.pem`: Public verification key.

If `--out-dir` is omitted, keys are written to the current working directory (`./private.pem` and `./public.pem`).

---

### Step B: Packaging Files or Directories (`pack`)

B2CHKS automatically applies high-speed stream compression (`gzip` for single files, `tar.gz` for directories) and processes chunks across CPU cores using a multi-threaded pipeline before splitting data into user-specified chunk sizes.

> **Note:** The `--chunk-size` (or `-c`) flag is required. You can specify sizes using human-readable units like `500k`, `100m`, `1g`, `2gb`.

#### 1. Unencrypted packaging:
```bash
python core.py pack ./my_game_folder --chunk-size 500m --author "arcxan"
```
*Note: If `--private-key` is not specified, B2CHKS automatically checks for a `private.pem` file in the current working directory or output directory. You can also pass `--keygen` to generate a keypair on the fly during packing.*

#### 2. Encrypted packaging (AES-256-GCM + Anti-Brute-Force scrypt):
```bash
python core.py pack ./my_game_folder --chunk-size 500m --encrypt-key "MySecretPassphrase123"
```
*By default, passwords use the memory-hard `scrypt` Key Derivation Function (N=16384, r=8, p=1). Memory hardness prevents GPU, FPGA, and ASIC cluster attacks from brute-forcing passphrases.*

#### Output Structure:
The command produces:
- `manifest.json`: Metadata, package information, cryptographic hashes, encryption parameters, and signature.
- `chunk_000.bin`, `chunk_001.bin`, ...: Size-bounded chunks.

---

### Step C: Verifying Packages (`verify`)

Verify chunk integrity and authorship before extraction:
```bash
python core.py verify manifest.json --public-key public.pem
```
- Scans the directory for matching chunk files by SHA-256 hash.
- Flags any missing or corrupted chunk files.
- Cryptographically validates the Ed25519 signature against the manifest content.
- If no manifest argument is provided, automatically locates `manifest.json` in the current directory.

---

### Step D: Extracting Packages (`extract`)

Extracting automatically performs pre-flight verification, parallel decryption (if encrypted), reassembly, and decompression in one seamless step:

#### 1. Unencrypted Package Extraction:
```bash
python core.py extract manifest.json --output-dir ./extracted
```

#### 2. Encrypted Package Extraction:
*Via interactive secure prompt:*
```bash
python core.py extract manifest.json
# Prompts: This package is cryptographically locked. Enter decryption key:
```

*Via CLI flag:*
```bash
python core.py extract manifest.json --decrypt-key "MySecretPassphrase123"
```

---

## 4. Embedding B2CHKS in Applications (Python SDK)

B2CHKS is designed as an open, embeddable SDK that can be directly imported into GUI apps (PySide, PyQt, Tkinter, Electron), background services, or custom scripts:

```python
import b2chks
from b2chks import B2CHKS

# 1. Generate keys
priv_file, pub_file = B2CHKS.keygen(author="developer", out_dir="./keys")

# 2. Define a progress callback (ideal for GUI progress bars)
def on_progress(current, total, stage):
    percent = (current / total) * 100
    print(f"[{stage.upper()}] {current}/{total} ({percent:.1f}%)")

# 3. Pack with encryption, multi-threading, and progress updates
manifest_path = B2CHKS.pack(
    source="./my_files",
    chunk_size="100m",
    output_dir="./dist",
    encrypt_key="AppSecretKey",
    private_key=priv_file,
    author="developer",
    progress_callback=on_progress,
)

# 4. Verify package
is_valid = B2CHKS.verify(
    manifest="./dist/manifest.json",
    public_key=pub_file,
    progress_callback=on_progress,
)

# 5. Extract package
success = B2CHKS.extract(
    manifest="./dist/manifest.json",
    output_dir="./extracted",
    decrypt_key="AppSecretKey",
    progress_callback=on_progress,
)
```

---

## 5. Security & Architecture Details

- **Protocol identifier:** `"b2chks"`
- **Anti-Brute-Force Memory-Hard KDF:**
  - Employs `scrypt` (N=16384, r=8, p=1) deriving 256-bit AES keys.
  - Requires large memory allocation per attempt, rendering GPU and ASIC dictionary/brute-force attacks computationally infeasible.
  - Full backwards compatibility with `PBKDF2-HMAC-SHA256`.
- **Chunk Encryption (Hybrid Model):**
  - Salt & KDF parameters stored in `manifest.json`.
  - Each chunk file encapsulates: `[12-byte nonce] + [ciphertext + 16-byte GCM authentication tag]`.
  - Authenticated chunk index bound into GCM AAD prevents chunk reordering or cross-package splicing.
- **Signatures:**
  - Ed25519 signature over deterministic canonical JSON of `manifest.json` (excluding `security.signature`).
- **Cross-Platform Compatibility:**
  - Standardized on UTF-8 and POSIX/Windows path handling with Pathlib.
  - Built-in pure-Python RFC 8032 Ed25519 and NIST SP 800-38D AES-GCM engine for zero-dependency execution.
  - Automatically utilizes `cryptography` C-extensions if installed for maximum hardware acceleration.
- **High-Throughput Parallel Pipeline:**
  - Multi-threaded chunk encryption, hashing, verification, and decryption via `concurrent.futures`.
