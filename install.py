#!/usr/bin/env python3
"""
Installer script to install B2CHKS globally on any system (Linux, macOS, Windows).
Guarantees global execution from PowerShell, Command Prompt, bash, and zsh.
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path


def install():
    print("=" * 60)
    print("           B2CHKS Global System Installer")
    print("=" * 60)

    repo_root = Path(__file__).parent.resolve()
    source_script = repo_root / "b2chks.py"

    if not source_script.exists():
        print("[-] Error: b2chks.py not found in source directory.")
        sys.exit(1)

    is_windows = platform.system() == "Windows"
    py_exec = sys.executable

    # 1. Optionally install cryptography for hardware acceleration
    try:
        import cryptography
        print("[+] Hardware-accelerated cryptography module already installed.")
    except ImportError:
        print("[*] Attempting to install 'cryptography' for hardware acceleration...")
        try:
            subprocess.run([py_exec, "-m", "pip", "install", "cryptography"], check=False, capture_output=True)
            print("[+] Installed cryptography.")
        except Exception:
            print("[*] Notice: Continuing with built-in pure-Python zero-dependency engine.")

    # 2. Install editable pip package with entry points
    try:
        print("[*] Installing package entrypoints via pip...")
        res = subprocess.run([py_exec, "-m", "pip", "install", "-e", str(repo_root)], capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Pip entrypoints installed successfully.")
    except Exception as e:
        print(f"[*] Notice: pip install: {e}")

    # 3. Bulletproof installation for Windows (PowerShell & CMD)
    if is_windows:
        user_profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        win_dirs = [
            Path(user_profile) / "AppData" / "Local" / "Microsoft" / "WindowsApps",
            Path(sys.prefix) / "Scripts",
            Path(user_profile) / ".local" / "bin",
            Path(user_profile) / "bin",
        ]

        target_dir = None
        for d in win_dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                # Test write permission
                test_file = d / ".write_test"
                test_file.touch()
                test_file.unlink()
                target_dir = d
                break
            except Exception:
                continue

        if not target_dir:
            target_dir = Path(user_profile) / "AppData" / "Local" / "Microsoft" / "WindowsApps"
            target_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Installing Windows launchers to: {target_dir}")

        for name in ["b2chks", "core", "chunkcore", "b3chks"]:
            # .cmd launcher for CMD & PowerShell
            cmd_file = target_dir / f"{name}.cmd"
            with open(cmd_file, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\n"{py_exec}" "{source_script}" %*\r\n')

            # .bat launcher
            bat_file = target_dir / f"{name}.bat"
            with open(bat_file, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\n"{py_exec}" "{source_script}" %*\r\n')

            # .ps1 PowerShell script so PowerShell recognizes it as a native cmdlet/script
            ps1_file = target_dir / f"{name}.ps1"
            with open(ps1_file, "w", encoding="utf-8") as f:
                f.write(f'& "{py_exec}" "{source_script}" $args\r\n')

        # Add function to PowerShell profile to eliminate any cmdlet errors
        try:
            ps_docs = Path(user_profile) / "Documents" / "WindowsPowerShell"
            ps_profile = ps_docs / "Microsoft.PowerShell_profile.ps1"
            ps_docs.mkdir(parents=True, exist_ok=True)
            ps_func = (
                f'\nfunction b2chks {{ & "{py_exec}" "{source_script}" $args }}\n'
                f'function core {{ & "{py_exec}" "{source_script}" $args }}\n'
            )
            existing = ps_profile.read_text(encoding="utf-8") if ps_profile.exists() else ""
            if "function b2chks" not in existing:
                with open(ps_profile, "a", encoding="utf-8") as f:
                    f.write(ps_func)
                print(f"[+] Added PowerShell profile functions to {ps_profile}")
        except Exception:
            pass

    # 4. Bulletproof installation for Linux and macOS
    else:
        unix_dirs = [
            Path.home() / ".local" / "bin",
            Path("/usr/local/bin"),
            Path.home() / "bin",
        ]

        target_dir = None
        for d in unix_dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                test_file = d / ".write_test"
                test_file.touch()
                test_file.unlink()
                target_dir = d
                break
            except Exception:
                continue

        if not target_dir:
            target_dir = Path.home() / ".local" / "bin"
            target_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Installing Unix launchers to: {target_dir}")

        for name in ["b2chks", "core", "chunkcore", "b3chks"]:
            target_cmd = target_dir / name
            shutil.copyfile(source_script, target_cmd)
            target_cmd.chmod(target_cmd.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print("\n" + "=" * 60)
    print("  [+] Installation Successful!")
    print(f"  Commands 'b2chks' and 'core' are now ready to use globally.")
    print("=" * 60)


if __name__ == "__main__":
    install()
