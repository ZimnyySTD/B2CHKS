#!/usr/bin/env python3
"""Clean, simple Command Line Interface (CLI) for B2CHKS."""
import argparse
import sys
from pathlib import Path
from typing import Optional, List

from b2chks.engine import B2CHKS
from b2chks.exceptions import B2CHKSError
from b2chks.extractor import verify, extract
from b2chks.packer import pack
from b2chks.signing import generate_keypair
from cli.progress import ProgressRenderer


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

    # 1. keygen
    parser_keygen = subparsers.add_parser("keygen", help="Generate Ed25519 signing keypair")
    parser_keygen.add_argument("--author", "-a", type=str, default="author", help="Author/developer identifier")
    parser_keygen.add_argument("--out-dir", "-o", type=str, default=".", help="Output directory for keys")

    # 2. pack
    parser_pack = subparsers.add_parser("pack", help="Create a standard ZIP or a chunked B2CHKS package")
    parser_pack.add_argument("source", type=str, help="Path to file or directory to pack")
    parser_pack.add_argument(
        "--chunk-size", "-c",
        dest="chunk_size",
        type=str,
        default=None,
        help="Size of each chunk. If omitted without --nochunks, create a standard ZIP archive.",
    )
    parser_pack.add_argument(
        "--nochunks", "--no-chunks",
        dest="nochunks",
        action="store_true",
        help="Create a single B2CHKS chunk with a manifest",
    )
    parser_pack.add_argument("--encrypt-key", "-e", dest="encrypt_key", type=str, default=None, help="Passphrase to encrypt with AES-256-GCM")
    parser_pack.add_argument("--kdf", type=str, choices=["scrypt", "pbkdf2"], default="scrypt", help="Key derivation function (default: scrypt)")
    parser_pack.add_argument("--compression", type=str, choices=["zstd"], default="zstd", help="B2CHKS compression (Zstandard)")
    parser_pack.add_argument(
        "--compression-level",
        type=int,
        default=9,
        help="Lossless compression strength: ZIP 0-9, Zstandard -5-22 (default: 9)",
    )
    parser_pack.add_argument("--private-key", "-k", dest="private_key", type=str, default=None, help="Path to Ed25519 private.pem to sign manifest")
    parser_pack.add_argument("--author", "-a", type=str, default=None, help="Author/Developer ID for manifest")
    parser_pack.add_argument("--output-dir", "-o", dest="output_dir", type=str, default=None, help="Output directory for package and manifest")
    parser_pack.add_argument("--workers", "-w", type=int, default=None, help="Number of worker threads (default: auto)")
    parser_pack.add_argument("--keygen", dest="generate_key", action="store_true", help="Automatically generate keypair if none exists and sign")
    parser_pack.add_argument("--no-progress", action="store_true", help="Disable progress display")
    parser_pack.add_argument("--quiet", action="store_true", help="Show errors only")
    parser_pack.add_argument("--json", action="store_true", help="Emit machine-readable progress events")

    # 3. verify
    parser_verify = subparsers.add_parser("verify", help="Verify package integrity and author signature")
    parser_verify.add_argument("manifest", type=str, nargs="?", default=None, help="Path to manifest.json or directory containing it")
    parser_verify.add_argument("--chunks-dir", "-d", dest="chunks_dir", type=str, default=None, help="Directory containing chunk files")
    parser_verify.add_argument("--public-key", "-k", dest="public_key", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")
    parser_verify.add_argument("--workers", "-w", type=int, default=None, help="Number of worker threads (default: auto)")
    parser_verify.add_argument("--trusted-public-key", type=str, default=None, help="Require signature to match this trusted key")
    parser_verify.add_argument("--no-progress", action="store_true", help="Disable progress display")
    parser_verify.add_argument("--quiet", action="store_true", help="Show errors only")
    parser_verify.add_argument("--json", action="store_true", help="Emit machine-readable progress events")

    # 4. extract
    parser_extract = subparsers.add_parser("extract", help="Verify, decrypt, assemble, and decompress package in one go")
    parser_extract.add_argument("manifest", type=str, nargs="?", default=None, help="Path to manifest.json or directory containing it")
    parser_extract.add_argument("--chunks-dir", "-d", dest="chunks_dir", type=str, default=None, help="Directory containing chunk files")
    parser_extract.add_argument("--output-dir", "-o", dest="output_dir", type=str, default=None, help="Destination directory for extracted files")
    parser_extract.add_argument("--decrypt-key", "-e", dest="decrypt_key", type=str, default=None, help="Decryption key passphrase (prompts if omitted and encrypted)")
    parser_extract.add_argument("--public-key", "-k", dest="public_key", type=str, default=None, help="Path to Ed25519 public.pem to verify signature")
    parser_extract.add_argument("--workers", "-w", type=int, default=None, help="Number of worker threads (default: auto)")
    parser_extract.add_argument("--trusted-public-key", type=str, default=None, help="Require signature to match this trusted key")
    parser_extract.add_argument("--memory-limit", type=int, default=None, help="Optional extraction memory budget in bytes")
    parser_extract.add_argument("--max-output-size", type=int, default=None, help="Optional uncompressed output limit in bytes")
    parser_extract.add_argument("--max-files", type=int, default=None, help="Optional archive member limit")
    parser_extract.add_argument("--max-file-size", type=int, default=None, help="Optional individual file-size limit in bytes")
    parser_extract.add_argument("--max-compression-ratio", type=float, default=None, help="Optional output/input ratio limit")
    parser_extract.add_argument("--no-progress", action="store_true", help="Disable progress display")
    parser_extract.add_argument("--quiet", action="store_true", help="Show errors only")
    parser_extract.add_argument("--json", action="store_true", help="Emit machine-readable progress events")

    # 5. uninstall
    subparsers.add_parser("uninstall", help="Uninstall B2CHKS globally from system")

    args = parser.parse_args(raw_argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "keygen":
            priv, pub = generate_keypair(args.author, args.out_dir)
            print(f"[+] Generated Ed25519 keypair for author '{args.author}':")
            print(f"    Private key: {priv}")
            print(f"    Public key:  {pub}")

        elif args.command == "pack":
            progress = ProgressRenderer(
                enabled=sys.stderr.isatty() and not args.no_progress,
                json_mode=args.json,
                quiet=args.quiet,
            )
            pack(
                source=args.source,
                chunk_size_str=args.chunk_size,
                nochunks=args.nochunks,
                output_dir=args.output_dir,
                encrypt_key=args.encrypt_key,
                private_key_path=args.private_key,
                author=args.author,
                generate_key=args.generate_key,
                compression=args.compression,
                compression_level=args.compression_level,
                kdf=args.kdf,
                workers=args.workers,
                progress_callback=progress.callback,
            )
            progress.finish()

        elif args.command == "verify":
            progress = ProgressRenderer(
                enabled=sys.stderr.isatty() and not args.no_progress,
                json_mode=args.json,
                quiet=args.quiet,
            )
            ok = verify(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                public_key_path=args.public_key,
                workers=args.workers,
                trusted_public_key_path=args.trusted_public_key,
                progress_callback=progress.callback,
            )
            progress.finish()
            if not ok:
                sys.exit(1)

        elif args.command == "extract":
            progress = ProgressRenderer(
                enabled=sys.stderr.isatty() and not args.no_progress,
                json_mode=args.json,
                quiet=args.quiet,
            )
            ok = extract(
                manifest_path=args.manifest,
                chunks_dir=args.chunks_dir,
                output_dir=args.output_dir,
                decrypt_key=args.decrypt_key,
                public_key_path=args.public_key,
                workers=args.workers,
                trusted_public_key_path=args.trusted_public_key,
                memory_budget_bytes=args.memory_limit,
                max_output_size=args.max_output_size,
                max_files=args.max_files,
                max_file_size=args.max_file_size,
                max_compression_ratio=args.max_compression_ratio,
                progress_callback=progress.callback,
            )
            progress.finish()
            if not ok:
                sys.exit(1)

        elif args.command == "uninstall":
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
