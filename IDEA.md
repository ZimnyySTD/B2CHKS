# Project Specification: **ChunkCore Protocol**

---

## 1. Executive Summary & Project Vision

**ChunkCore** is a next-generation, high-performance file packaging, chunking, and secure distribution protocol designed to replace clunky legacy split archives (like `.rar` or `.7z` volumes) with a modern, decoupled, and cryptographically secure architecture.

Traditional archive formats bundle data and structure together, forcing creators to know final hosting locations upfront, while lacking flexible mechanisms for offline verification, modular integrity checks, and developer authentication.

ChunkCore solves this by separating **packaging** from **hosting**. A creator can pack any single file or entire directory locally into size-limited chunks and a lightweight manifest file. These chunks can then be uploaded anywhere across the internet (cloud drives, mirrors, personal servers) without hardcoding URLs. A user or client application can then gather those chunks, verify them via cryptographic hashes, optionally decrypt them using AES-256-GCM, and seamlessly reassemble the original data.

---

## 2. Core Architecture & Workflow

The system is built around a modular command-line interface (CLI) core that handles stream processing, cryptography, manifest generation, and file reconstruction.

### Phase A: Packaging & Signing (The Creator Side)

1. **Source Selection:** The developer targets either a **single file** or an **entire directory**.
2. **Dynamic Chunking:** The tool reads the data stream and splits it into strict, user-defined chunk sizes (e.g., 100MB, 500MB, 2GB).
3. **Optional Encryption (AES-256-GCM):** If the developer chooses to lock the build, the chunks are encrypted using a 256-bit key derived from a custom passphrase. This ensures that unauthorized users cannot read or extract the raw contents without the key.
4. **Hashing & Integrity:** Every individual chunk is processed to generate a unique **SHA-256 cryptographic hash**, ensuring absolute tamper-resistance.
5. **Developer Signing (Ed25519):** The developer signs the entire manifest using an asymmetric private key, embedding a cryptographic proof of authorship.
6. **Manifest Generation:** A clean, human-readable `.json` manifest is outputted, containing package metadata, encryption flags, chunk hashes, and signature data.

### Phase B: Distribution & Ingestion (The Internet)

* **Decoupled Uploads:** The creator uploads the generated chunk files (`chunk_000.bin`, `chunk_001.bin`, etc.) and the `manifest.json` to any hosting environment of their choice.
* **Flexible Gathering:** End-users can manually place downloaded chunks into a local staging directory alongside the manifest, or feed the manifest into an automated downloader that fetches chunks one by one.

### Phase C: Pre-Flight Verification & Extraction (The Consumer Side)

1. **Inventory Scan:** The core engine reads the `manifest.json` and scans the local directory for matching chunk files (relying on cryptographic hashes rather than strict filenames).
2. **Integrity & Completeness Check:** The software instantly highlights missing chunks or corrupted downloads before writing anything to disk.
3. **Cryptographic Decryption Prompt:** If the package is locked, the CLI securely prompts the user:
> *"This package is cryptographically locked. Enter decryption key:"*


4. **Seamless Reassembly:** Once verified and decrypted, the core reconstructs the exact original file or folder structure in a target destination folder.

---

## 3. Cryptographic Key Management & Workflows

To ensure maximum security, authorship verification, and data confidentiality, ChunkCore relies on a dual-cryptography model separating **identity (signing)** from **payload security (encryption)**.

### How Developers Get and Manage Keys

#### 1. Author Identity & Signing Keys (Ed25519)

* **What it is:** An asymmetric keypair consisting of a **Private Key** (kept secret by the developer) and a **Public Key** (shared globally or embedded in creator profiles).
* **How to get them:** Developers generate a local keypair using the ChunkCore CLI tool:
```bash
python core.pykeygen --author "arcxan"

```


This outputs a `private.pem` (stored securely on the developer's machine) and a `public.pem`.
* **How it works:** When packing a release, the CLI automatically signs the manifest hash using the `private.pem`. Anyone extracting the package can use the creator's `public.pem` to verify that the files genuinely originated from that developer and have not been altered in transit.

#### 2. Package Encryption Keys (AES-256-GCM)

* **What it is:** A symmetric 256-bit key used to lock the actual payload data inside the chunks.
* **How to get them:** The developer defines a custom secure passphrase or secret string when executing the packing command:
```bash
python core.py pack ./my_game_folder --chunk-size 500m --encrypt-key "MySecretPassphrase123"

```


* **How it works:** The CLI uses a Key Derivation Function (like PBKDF2) to turn that passphrase into a robust AES-256 key.
* **The Extraction Handshake:** When an end-user runs the extraction tool on an encrypted package, the core CLI pauses, requests the exact secret passphrase, derives the matching AES key, and decrypts the chunks on-the-fly during reassembly. If an incorrect key is provided, the cryptographic authentication layer (GCM mode) instantly rejects it, protecting against brute-force attacks and corrupted data states.

---

## 4. Technical Manifest Schema Design (`manifest.json`)

The universal blueprint for a ChunkCore package is designed to be lightweight, transparent, and completely decoupled from storage locations:

```json
{
  "protocol": "chunk-core-v1",
  "package_info": {
    "name": "ProjectBuild_v1.0.iso",
    "source_type": "file", 
    "total_size_bytes": 2147483648,
    "chunk_size_bytes": 524288000,
    "total_chunks": 5,
    "encrypted": true
  },
  "security": {
    "developer_id": "arcxan",
    "public_key": "ed25519_pub_key_hex_string...",
    "signature": "sig_hex_string_proving_authorship..."
  },
  "chunks": [
    {
      "index": 0,
      "filename": "chunk_000.bin",
      "size": 524288000,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      "index": 1,
      "filename": "chunk_001.bin",
      "size": 524288000,
      "sha256": "d7a8fbb307d7809469ca9abcb0082e4f8d5651ea46dcdcdf1d8f5d08251d7c3b"
    }
  ]
}

```

---

## 5. Future Roadmap & Extensibility

While the immediate focus is a robust Python-based CLI core, the protocol's clean JSON schema and modular engine design pave the way for future integrations:

* **GUI Wrappers:** Building cross-platform desktop interfaces on top of the Python core to provide drag-and-drop packaging, visual progress bars, and rich pre-extraction previews.
* **Decentralized Extensions:** Interfacing the chunk hashes with peer-to-peer distribution networks or content-addressable storage layers.
* **Ecosystem Compatibility:** Allowing other community tools and scripts to parse `.bundle` manifests natively, creating a universal sharing standard.
