#!/usr/bin/env python3
"""Command Line Interface (CLI) for B2CHKS."""
import argparse
import sys
from pathlib import Path
from typing import Optional, List

from b2chks.engine import B2CHKS
from b2chks.exceptions import B2CHKSError
from b2chks.extractor import verify, extract
from b2chks.packer import pack
from b2chks.signing import generate_keypair


def main(custom_argv: Optional[List[str]] = None):
    raw_argv = list(sys.argv[1:]) if custom_argv is None else list(custom_argv)
    prog_name = Path(sys.argv[0]).name

    if "keygen" in prog_name and ("keygen" not in raw_argv) and ("-h" not in raw_argv) and ("--help" not in raw_argv):
        raw_argv.insert(0, "keygen")

    parser = argparse.ArgumentParser(
        prog="b2chks",
        description="B2CHKS: High-performance file packaging, chunking, compression, and distribution tool.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    for sub in ["keygen", "key-gen", "genkey"]:
        parser_keygen = subparsers.add_parser(sub, help="Generate Ed25519 signing keypair")
        parser_keygen.add_argument("--author", "-a", type=str, default="author", help="Author/developer identifier")
        parser_keygen.add_argument("--out-dir", "-o", type=str, default=".", help="Output directory for keys")

    for name in ["pack", "package", "compress"]:
        parser_pack = subparsers.add_parser(name, help="Compress, chunk, encrypt and sign a file or directory")
        parser_pack.add_argument("source", type=str, help="Path to file or directory to pack")
        parser_pack.add_argument(
            "--chunk-size", "--chunk_size", "-c", "--size",
            dest="chunk_size",
            type=str,
            required=True,
            help="Size of each chunk (e.g. 100m, 500m, 1g, 500k). Required.",
        )
        parser_pack.add_argument("--encrypt-key", "--encrypt_key", "-e", dest="encrypt_key", type=str, default=None, help="Passphrase to encrypt chunks with AES-256-GCM")
        parser_pack.add_argument("--kdf", type=str, choices=["scrypt", "pbkdf2"], default="scrypt", help="Key derivation function (default: scrypt anti-brute-force)")
        parser_pack.add_argument("--compression", type=str, choices=["gzip", "zstd"], default="gzip", help="Compression algorithm (default: gzip, optional: zstd)")
        parser_pack.add_argument("--private-key", "--private_key", "-k", "--key", dest="private_key", type=str, default=None, help="Path to Ed25519 private.pem to sign manifest")
        parser_pack.add_argument("--author", "-a", type=str, default=None, help="Author/Developer ID for manifest")
        parser_pack.add_argument("--output-dir", "--output_dir", "-o", dest="output_dir", type=str, default=None, help="Output directory for chunks and manifest (defaults to current dir)")
        parser_pack.add_argument("--workers", "-w", type=int, default=None, help="Number of worker threads (default: auto)")
        parser_pack.add_argument("--keygen", "--generate-key", dest="generate_key", action="store_true", help="Automatically generate keypair if none exists and sign package")

    for name in ["verify", "check"]:
        parser_verify = subparsers.add_parser(name, help="Verify chunk integrity and author signature")
        parser_verify.add_argument("manifest", type=str, nargs="?", default=None, help="Path to manifest.json or directory containing it")
        parser_verify.add_argument("--chunks-dir", "--chunks_dir", "-d", dest="chunks_dir", type=str, default=None, help="Directory containing chunk files")
        parser_verify.add_argument("--public-key", "--public_key", "-k", dest="public_key", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")
        parser_verify.add_argument("--workers", "-w", type=int, default=None, help="Number of worker threads (default: auto)")

    for name in ["extract", "unpack", "decompress"]:
        parser_extract = subparsers.add_parser(name, help="Verify, decrypt, assemble, and decompress package")
        parser_extract.add_argument("manifest", type=str, nargs="?", default=None, help="Path to manifest.json or directory containing it")
        parser_extract.add_argument("--chunks-dir", "--chunks_dir", "-d", dest="chunks_dir", type=str, default=None, help="Directory containing chunk files")
        parser_extract.add_argument("--output-dir", "--output_dir", "-o", dest="output_dir", type=str, default=None, help="Destination directory for extracted files")
        parser_extract.add_argument("--decrypt-key", "--decrypt_key", "-e", dest="decrypt_key", type=str, default=None, help="Decryption key passphrase (prompts if omitted and encrypted)")
        parser_extract.add_argument("--public-key", "--public_key", "-k", dest="public_key", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")
        parser_extract.add_argument("--workers", "-w", type=int, default=None, help="Number of worker threads (default: auto)")

    for name in ["uninstall", "remove"]:
        subparsers.add_parser(name, help="Uninstall B2CHKS globally from system")

    args = parser.parse_args(raw_argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command in ["keygen", "key-gen", "genkey"]:
            priv, pub = generate_keypair(args.author, args.out_dir)
            print(f"[+] Generated Ed25519 keypair for author '{args.author}':")
            print(f"    Private key: {priv}")
            print(f"    Public key:  {pub}")

        elif args.command in ["pack", "package", "compress"]:
            pack(
                source=args.source,
                chunk_size_str=args.chunk_size,
                output_dir=args.output_dir,
                encrypt_key=args.encrypt_key,
                private_key_path=args.private_key,
                author=args.author,
                generate_key=args.generate_key,
                compression=args.compression,
                kdf=args.kdf,
                workers=args.workers,
            )

        elif args.command in ["verify", "check"]:
            ok = verify(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                public_key_path=args.public_key,
                workers=args.workers,
            )
            if not ok:
                sys.exit(1)

        elif args.command in ["extract", "unpack", "decompress"]:
            ok = extract(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                output_dir=args.output_dir,
                decrypt_key=args.decrypt_key,
                public_key_path=args.public_key,
                workers=args.workers,
            )
            if not ok:
                sys.exit(1)

        elif args.command in ["uninstall", "remove"]:
            try:
                import install
            except ImportError:
                sys.path.insert(0, str(Path(__file__).parent.parent))
                import install
            ok = install.uninstall()
            if not ok:
                sys.exit(1)

    except B2CHKSError as e:
        print(f"[-] B2CHKS Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
