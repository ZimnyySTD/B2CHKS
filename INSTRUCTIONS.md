# B2CHKS Protocol Instructions & Guide

**B2CHKS** is a high-performance file packaging, chunking, compression, and secure distribution protocol and tool. It decouples packaging from hosting, allowing creators to compress, split, optionally encrypt (AES-256-GCM), and cryptographically sign (Ed25519) any file or directory into lightweight chunks and a JSON manifest.

---

## 1. Installation & Requirements

- **Python**: Version 3.8+ (tested on Python 3.12)
- **Dependencies**: `cryptography`

Install required dependencies:
```bash
pip install cryptography
```

Ensure the CLI script is executable:
```bash
chmod +x b2chks.py
```

---

## 2. CLI Overview & Commands

`b2chks.py` provides four primary subcommands:
1. `keygen`: Generate an Ed25519 keypair for author signing and verification.
2. `pack` (aliases: `package`, `compress`): Compress, chunk, optionally encrypt, and sign a file or directory.
3. `verify`: Inspect chunk inventory, verify SHA-256 chunk hashes, and validate manifest authorship signature.
4. `extract`: Verify, decrypt (if encrypted), reassemble, and decompress the package in one go.

Run `./b2chks.py --help` or `./b2chks.py <subcommand> --help` to see detailed options.

---

## 3. Step-by-Step Usage Guide

### Step A: Generating Developer Signing Keys

To prove authenticity of packages you create:
```bash
./b2chks.py keygen --author "arcxan" --out-dir ./keys
```
- Outputs:
  - `private.pem`: Keep this private on your developer machine.
  - `public.pem`: Share this public key or embed it in developer profiles.

If `--out-dir` is omitted, keys are written to the current working directory (`./private.pem` and `./public.pem`).

---

### Step B: Packaging Files or Directories (`pack` / `package` / `compress`)

B2CHKS automatically applies compression (`gzip` for single files, `tar.gz` for directories) before splitting data into user-specified chunk sizes.

> **Note:** The `--chunk-size` flag is required. You can specify sizes using human-readable units like `500k`, `100m`, `1g`.

#### 1. Unencrypted packaging:
```bash
./b2chks.py pack ./my_game_folder \
  --chunk-size 500m \
  --output-dir ./dist \
  --author "arcxan" \
  --private-key ./keys/private.pem
```
*Note: If `--private-key` is omitted, `b2chks.py` automatically checks for a `private.pem` file in the current working directory. If none is found, it packs without signing.*

#### 2. Encrypted packaging (AES-256-GCM):
```bash
./b2chks.py pack ./my_game_folder \
  --chunk-size 500m \
  --encrypt-key "MySecretPassphrase123" \
  --output-dir ./dist \
  --author "arcxan" \
  --private-key ./keys/private.pem
```

#### Output Structure:
In `./dist`, you will find:
- `manifest.json`: Metadata, package information, cryptographic hashes, encryption parameters, and signature.
- `chunk_000.bin`, `chunk_001.bin`, ...: Size-bounded chunks.

---

### Step C: Verifying Packages (`verify`)

Before extracting or distributing, anyone can verify the package integrity and authenticity:

```bash
./b2chks.py verify ./dist/manifest.json --public-key ./keys/public.pem
```

- Scans the directory for matching chunk files by SHA-256 hash.
- Flags any missing or corrupted chunk files.
- Cryptographically validates the Ed25519 signature against the manifest content.

---

### Step D: Extracting Packages (`extract`)

Extracting automatically performs pre-flight verification, decryption (if encrypted), reassembly, and decompression in one seamless step:

#### 1. Unencrypted Package Extraction:
```bash
./b2chks.py extract ./dist/manifest.json --output-dir ./extracted
```

#### 2. Encrypted Package Extraction:
You can pass the key directly or omit it to be securely prompted:

*Via secure prompt:*
```bash
./b2chks.py extract ./dist/manifest.json --output-dir ./extracted
# Prompts: This package is cryptographically locked. Enter decryption key:
```

*Via CLI flag:*
```bash
./b2chks.py extract ./dist/manifest.json --output-dir ./extracted --decrypt-key "MySecretPassphrase123"
```

If an author's public key is available, pass `--public-key ./keys/public.pem` to ensure signature verification occurs during extraction.

---

## 4. Technical Architecture Details

- **Protocol identifier:** `"b2chks"`
- **Compression:**
  - Files: Raw file compressed via gzip stream.
  - Directories: Full directory structure archived as POSIX tar.gz.
- **Chunk Encryption (Hybrid Model):**
  - Salt & PBKDF2 parameters stored in `manifest.json`.
  - PBKDF2-HMAC-SHA256 derives 256-bit AES key (600,000 iterations).
  - Each chunk file encapsulates: `[12-byte nonce] + [ciphertext + 16-byte GCM authentication tag]`.
  - Authenticated chunk index bound into GCM AAD prevents chunk reordering or cross-package splicing.
- **Signatures:**
  - Ed25519 signature over deterministic canonical JSON of `manifest.json` (excluding `security.signature`).
