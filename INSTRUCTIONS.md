# B2CHKS Protocol Instructions & Guide

**B2CHKS** is a cross-platform, high-performance file packaging, chunking, compression, and secure distribution protocol and CLI tool. It decouples packaging from hosting, allowing creators to compress, split, optionally encrypt (AES-256-GCM), and cryptographically sign (Ed25519) any file or directory into lightweight chunks and a JSON manifest.

---

## 1. Installation & Requirements

- **Python**: Version 3.8+ (Linux, macOS, Windows)
- **Zero-Dependency Support**: B2CHKS includes pure-Python implementations of Ed25519 and AES-256-GCM. It runs out of the box using only Python's standard library.
- **Optional Acceleration**: If the `cryptography` package is installed (`pip install cryptography`), B2CHKS automatically accelerates cryptographic operations.

### Running Directly or Installing:
You can run `b2chks.py` directly:
```bash
python b2chks.py --help
# or via CLI aliases:
python core.py --help
```

Or install the package locally:
```bash
pip install -e .
b2chks --help
```

---

## 2. CLI Overview & Commands

B2CHKS provides the following primary subcommands:
1. `keygen` (aliases: `key-gen`, `genkey`): Generate an Ed25519 keypair for author signing and verification.
2. `pack` (aliases: `package`, `compress`): Compress, chunk, optionally encrypt, and sign a file or directory.
3. `verify` (alias: `check`): Inspect chunk inventory, verify SHA-256 chunk hashes, and validate manifest authorship signature.
4. `extract` (aliases: `unpack`, `decompress`): Verify, decrypt (if encrypted), reassemble, and decompress the package in one go.

Run `python b2chks.py --help` or `python core.py <subcommand> --help` to see detailed options.

---

## 3. Step-by-Step Usage Guide

### Step A: Generating Developer Signing Keys

To generate signing keys proving authorship:
```bash
python core.pykeygen --author "arcxan"
# or
python b2chks.py keygen --author "arcxan" --out-dir ./keys
```
- Outputs:
  - `private.pem`: Private signing key.
  - `public.pem`: Public verification key.

If `--out-dir` is omitted, keys are written to the current working directory (`./private.pem` and `./public.pem`).

---

### Step B: Packaging Files or Directories (`pack`)

B2CHKS automatically applies compression (`gzip` for single files, `tar.gz` for directories) before splitting data into user-specified chunk sizes.

> **Note:** The `--chunk-size` (or `-c`) flag is required. You can specify sizes using human-readable units like `500k`, `100m`, `1g`, `2gb`.

#### 1. Unencrypted packaging:
```bash
python core.py pack ./my_game_folder --chunk-size 500m --author "arcxan"
```
*Note: If `--private-key` is not specified, B2CHKS automatically checks for a `private.pem` file in the current working directory or output directory. You can also pass `--keygen` to generate a keypair on the fly during packing.*

#### 2. Encrypted packaging (AES-256-GCM):
```bash
python core.py pack ./my_game_folder --chunk-size 500m --encrypt-key "MySecretPassphrase123"
```

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

Extracting automatically performs pre-flight verification, decryption (if encrypted), reassembly, and decompression in one seamless step:

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

## 4. Technical Architecture Details

- **Protocol identifier:** `"b2chks"`
- **Compression:**
  - Files: Raw file compressed via gzip stream.
  - Directories: Full directory structure archived as POSIX tar.gz.
- **Chunk Encryption (Hybrid Model):**
  - Salt & PBKDF2 parameters stored in `manifest.json`.
  - PBKDF2-HMAC-SHA256 derives 256-bit AES key.
  - Each chunk file encapsulates: `[12-byte nonce] + [ciphertext + 16-byte GCM authentication tag]`.
  - Authenticated chunk index bound into GCM AAD prevents chunk reordering or cross-package splicing.
- **Signatures:**
  - Ed25519 signature over deterministic canonical JSON of `manifest.json` (excluding `security.signature`).
- **Cross-Platform Compatibility:**
  - Standardized on UTF-8 and POSIX/Windows path handling with Pathlib.
  - Built-in pure-Python RFC 8032 Ed25519 and NIST SP 800-38D AES-GCM engine for zero-dependency execution.
