# B2CHKS Protocol Instructions & Developer Guide

**B2CHKS** is a cross-platform, high-performance file packaging, chunking, compression, and secure distribution protocol, CLI tool, and embeddable Python SDK. It creates ordinary ZIP archives by default, or Zstandard-compressed B2CHKS packages when chunking or `--nochunks` is requested.

---

## 1. Quick Global Installation & Uninstallation

Install B2CHKS globally so that `b2chks` is available anywhere in PowerShell, Command Prompt, bash, or zsh:

### Automated Global Install (Linux, macOS, Windows)
```bash
python install.py
```
- If B2CHKS is already installed, running `install.py` automatically replaces and refreshes the installation cleanly.
- Installs and verifies native performance backends (`cryptography`).
- Configures native PowerShell launchers (`.ps1`, `.cmd`, `.bat`) and profile functions to prevent any "cmdlet not found" errors on Windows.

### Uninstallation (Only if Installed)
You can uninstall B2CHKS globally using either:
```bash
python uninstall.py
# or
b2chks uninstall
```
- Verifies if B2CHKS is currently installed. If not installed, informs the user cleanly without error.
- Removes all system launchers, PowerShell functions, and pip package artifacts.

---

## 2. Clean CLI Overview & Commands

B2CHKS provides 5 clean, simple subcommands:
1. `keygen`: Generate an Ed25519 keypair for author signing and verification.
2. `pack`: Compress, pack, optionally chunk, encrypt, and sign a file or directory.
3. `verify`: Inspect chunk inventory, verify SHA-256 chunk hashes in parallel, and validate manifest authorship signature.
4. `extract`: Verify, decrypt (if encrypted), reassemble, and decompress the package in one go.
5. `uninstall`: Remove B2CHKS globally from the system.

Run `b2chks --help` or `b2chks <subcommand> --help` to see detailed options.

---

## 3. Step-by-Step Usage Guide

### Step A: Generating Developer Signing Keys

To generate signing keys proving authorship:
```bash
b2chks keygen --author "arcxan" --out-dir ./keys
```
- Outputs:
  - `private.pem`: Private signing key.
  - `public.pem`: Public verification key.

If `--out-dir` is omitted, keys are written to the current working directory (`./private.pem` and `./public.pem`).

---

### Step B: Packaging Files or Directories (`pack`)

#### 1. Standard ZIP archive:
```bash
b2chks pack ./my_game_folder
```

#### 2. B2CHKS packaging without chunking (`--nochunks`):
To quickly compress a file or folder into a single package file without splitting:
```bash
b2chks pack ./my_game_folder --nochunks
```

#### 3. Packaging with Chunking (`--chunk-size`):
To split into size-bounded chunks (e.g. `500k`, `100m`, `1g`, `2gb`):
```bash
b2chks pack ./my_game_folder --chunk-size 100m
```

#### 4. Encrypted Packaging (AES-256-GCM + Anti-Brute-Force scrypt):
```bash
b2chks pack ./my_game_folder --nochunks --encrypt-key "MySecretPassphrase123"
# or with chunks:
b2chks pack ./my_game_folder --chunk-size 100m --encrypt-key "MySecretPassphrase123"
```

Zstandard is the only compression format used by B2CHKS packages.

---

### Step C: Verifying Packages (`verify`)

Verify chunk integrity and authorship before extraction:
```bash
b2chks verify manifest.json --public-key public.pem
```
- Concurrently scans and verifies chunk files by SHA-256 hash.
- Flags any missing or corrupted chunk files.
- Cryptographically validates the Ed25519 signature against the manifest content.
- If no manifest argument is provided, automatically locates `manifest.json` in the current directory.

---

### Step D: Extracting Packages (`extract`)

Extracting automatically performs pre-flight verification, parallel decryption (if encrypted), reassembly, and decompression in one seamless step:

#### 1. Unencrypted Package Extraction:
```bash
b2chks extract manifest.json --output-dir ./extracted
```

#### 2. Encrypted Package Extraction:
*Via interactive secure prompt:*
```bash
b2chks extract manifest.json
# Prompts: This package is cryptographically locked. Enter decryption key:
```

*Via CLI flag:*
```bash
b2chks extract manifest.json --decrypt-key "MySecretPassphrase123"
```

---

## 4. Embedding B2CHKS in Applications (Python SDK)

B2CHKS is designed as an open, embeddable SDK that can be directly imported into GUI apps (PySide, PyQt, Tkinter, Electron), background services, or custom scripts:

```python
from b2chks import B2CHKS

# 1. Fast pack without chunking
manifest_path = B2CHKS.pack(
    source="./my_files",
    nochunks=True,
    output_dir="./dist",
    encrypt_key="AppSecretKey",
)

# 2. Extract package
success = B2CHKS.extract(
    manifest=manifest_path,
    output_dir="./extracted",
    decrypt_key="AppSecretKey",
)
```

### Progress and safe extraction

The CLI renders phase progress only on interactive terminals and throttles
updates to avoid unnecessary CPU usage. Use `--quiet`, `--no-progress`, or
`--json` for automation. Extraction can optionally enforce limits and verify
against an external trusted signing key:

```bash
b2chks extract manifest.json \
  --trusted-public-key ./keys/public.pem \
  --max-output-size 100000000000 \
  --max-files 100000
```
