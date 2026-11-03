# B2CHKS Protocol Specification (v1.0)

---

## 1. Abstract
The **B2CHKS Protocol** defines an open, high-performance, and cryptographically secure format for packaging, compressing, chunking, and distributing files and directory trees. By decoupling data packaging from network hosting, B2CHKS enables offline integrity verification, developer authorship authentication, and tamper-resistant encrypted distribution across heterogeneous networks and storage providers.

---

## 2. Manifest Schema (`manifest.json`)

The manifest is a UTF-8 encoded JSON document describing the package topology, security credentials, and chunk hashes.

### JSON Schema

```json
{
  "protocol": "b2chks",
  "package_info": {
    "name": "ProjectBuild_v1.0.iso",
    "source_type": "file",
    "total_size_bytes": 2147483648,
    "chunk_size_bytes": 524288000,
    "total_chunks": 5,
    "encrypted": true,
    "compression": "gzip"
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "kdf": "scrypt",
    "salt": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "n": 16384,
    "r": 8,
    "p": 1
  },
  "security": {
    "developer_id": "arcxan",
    "public_key": "302a300506032b6570032100...",
    "signature": "8a39f1c7d2e0..."
  },
  "chunks": [
    {
      "index": 0,
      "filename": "chunk_000.bin",
      "size": 524288000,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

### Field Definitions & Types

#### `protocol` (string, required)
Identifier indicating protocol specification. Accepted values for backward compatibility:
- `"b2chks"` (default v1)
- `"b2chks-v1"`
- `"chunk-core-v1"` (legacy specification identifier)

#### `package_info` (object, required)
- `name` (string): Original source file or folder name.
- `source_type` (string): Type of source (`"file"` or `"directory"`).
- `total_size_bytes` (integer): Total uncompressed payload size in bytes.
- `chunk_size_bytes` (integer): Maximum user-defined target chunk payload size.
- `total_chunks` (integer): Total count of chunk files making up the archive.
- `encrypted` (boolean): `true` if chunk payloads are encrypted with AES-256-GCM, `false` otherwise.
- `compression` (string, optional): Stream compression algorithm used (`"gzip"` or `"zstd"`). Default is `"gzip"`.

#### `encryption` (object, required if `encrypted == true`)
- `algorithm` (string): Cryptographic cipher (`"AES-256-GCM"`).
- `kdf` (string): Key Derivation Function (`"scrypt"` or `"PBKDF2-HMAC-SHA256"`).
- `salt` (string, hex): 16-byte cryptographically secure pseudorandom salt.
- `n`, `r`, `p` (integers, optional): `scrypt` CPU and memory cost parameters (default: N=16384, r=8, p=1).
- `iterations` (integer, optional): Iteration count if PBKDF2 is selected (default: 100,000).

#### `security` (object, required)
- `developer_id` (string): Identifier of developer/author.
- `public_key` (string, hex): 32-byte Ed25519 public key in raw hex or SubjectPublicKeyInfo ASN.1 format.
- `signature` (string, hex): 64-byte Ed25519 cryptographic signature proving manifest authorship.

#### `chunks` (array of objects, required)
- `index` (integer): Zero-based sequential chunk index (`0, 1, 2, ...`).
- `filename` (string): Default formatted filename: `chunk_{index:03d}.bin`.
- `size` (integer): Exact size in bytes of the chunk file on disk.
- `sha256` (string, hex): SHA-256 digest of the chunk file.

---

## 3. Cryptographic Standards & Compatibility

### 3.1 Authorship Signature (Ed25519)
1. Manifest dictionary is duplicated and the `security.signature` key is removed.
2. Canonical JSON serialization:
   - Keys sorted lexicographically (`sort_keys=True`).
   - Compact separators with no extraneous whitespace: `separators=(',', ':')`.
   - UTF-8 byte encoding.
3. Ed25519 signature is generated over the canonical JSON bytes.
4. Anyone can verify authorship using the author's public key without requiring decryption keys.

### 3.2 Payload Encryption & Nonce Isolation (AES-256-GCM)
1. **Key Derivation**: 256-bit symmetric AES key derived using memory-hard `scrypt` (preventing GPU/ASIC password cracking).
2. **Chunk Binary Layout**:
   ```
   [12-byte Nonce] + [Ciphertext] + [16-byte GCM Authentication Tag]
   ```
3. **Associated Authenticated Data (AAD)**:
   The 4-byte big-endian representation of the chunk index is bound as AAD:
   ```
   AAD = uint32_be(chunk_index)
   ```
   *Security Guarantee:* Binding `chunk_index` into GCM authenticated data prevents chunk reordering, truncation, or cross-package splicing attacks.

---

## 4. Extraction & Reconstruction Pipeline
1. **Pre-flight Integrity**: Validates manifest schema and verifies every chunk's SHA-256 hash.
2. **Authorship Check**: If signature is present, verifies Ed25519 signature against public key.
3. **Decryption**: If encrypted, decrypts each chunk using derived AES key and verifies the GCM auth tag before decompression.
4. **Decompression**: Reassembles the unencrypted compressed stream and reconstructs original files or directory structures.
