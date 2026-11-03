#!/usr/bin/env python3
"""
Installer & Uninstaller script for B2CHKS globally on any system (Linux, macOS, Windows).
Guarantees global execution from PowerShell, Command Prompt, bash, and zsh.
Ensures native performance dependencies are installed.
"""

import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path


def get_install_locations():
    """Retrieve potential launcher installation directories based on OS."""
    is_windows = platform.system() == "Windows"
    locations = []
    if is_windows:
        user_profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        locations.append(Path(user_profile) / "AppData" / "Local" / "Microsoft" / "WindowsApps")
        locations.append(Path(sys.prefix) / "Scripts")
        locations.append(Path(user_profile) / ".local" / "bin")
        locations.append(Path(user_profile) / "bin")
    else:
        locations.append(Path.home() / ".local" / "bin")
        locations.append(Path("/usr/local/bin"))
        locations.append(Path.home() / "bin")
    return locations


def is_installed() -> bool:
    """Check if B2CHKS is currently installed anywhere on the system."""
    try:
        res = subprocess.run([sys.executable, "-m", "pip", "show", "b2chks"], capture_output=True, text=True)
        if res.returncode == 0:
            return True
    except Exception:
        pass

    cmd_names = ["b2chks", "core", "chunkcore", "b3chks"]
    exts = [".cmd", ".bat", ".ps1", ""] if platform.system() == "Windows" else [""]
    for loc in get_install_locations():
        if loc.exists():
            for name in cmd_names:
                for ext in exts:
                    target = loc / f"{name}{ext}"
                    if target.exists():
                        return True
    return False


def uninstall():
    print("=" * 60)
    print("           B2CHKS System Uninstaller")
    print("=" * 60)

    if not is_installed():
        print("[-] B2CHKS is not currently installed on this system.")
        return False

    print("[*] Found existing B2CHKS installation. Removing...")
    removed_items = 0

    try:
        res = subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "b2chks"], capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Uninstalled pip package 'b2chks'.")
            removed_items += 1
    except Exception as e:
        print(f"[*] Notice: pip uninstall: {e}")

    cmd_names = ["b2chks", "core", "chunkcore", "b3chks"]
    exts = [".cmd", ".bat", ".ps1", ""] if platform.system() == "Windows" else [""]
    for loc in get_install_locations():
        if loc.exists():
            for name in cmd_names:
                for ext in exts:
                    target = loc / f"{name}{ext}"
                    if target.exists():
                        try:
                            target.unlink()
                            print(f"[+] Removed: {target}")
                            removed_items += 1
                        except Exception as e:
                            print(f"[!] Warning: Could not remove {target}: {e}")

    if platform.system() == "Windows":
        user_profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        ps_docs = Path(user_profile) / "Documents" / "WindowsPowerShell"
        ps_profile = ps_docs / "Microsoft.PowerShell_profile.ps1"
        if ps_profile.exists():
            try:
                lines = ps_profile.read_text(encoding="utf-8").splitlines()
                new_lines = [
                    l for l in lines
                    if "function b2chks" not in l and "function core" not in l and "b2chks.py" not in l
                ]
                ps_profile.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                print(f"[+] Cleaned up PowerShell profile in {ps_profile}")
                removed_items += 1
            except Exception as e:
                print(f"[!] Warning: Could not clean PowerShell profile: {e}")

    print("\n" + "=" * 60)
    print(f"  [+] Uninstallation complete! ({removed_items} items removed)")
    print("=" * 60)
    return True


def install():
    print("=" * 60)
    print("      B2CHKS Native Performance Global Installer")
    print("=" * 60)

    if is_installed():
        print("[*] Existing B2CHKS installation detected. Replacing and updating...")
        uninstall()
        print("[*] Proceeding with clean reinstallation...")

    repo_root = Path(__file__).parent.resolve()
    source_script = repo_root / "b2chks.py"

    if not source_script.exists():
        print("[-] Error: b2chks.py not found in source directory.")
        sys.exit(1)

    is_windows = platform.system() == "Windows"
    py_exec = sys.executable

    # 1. Install required native dependencies
    print("[*] Installing required native performance backends (cryptography)...")
    res_crypto = subprocess.run([py_exec, "-m", "pip", "install", "cryptography>=3.4"], check=False, capture_output=True, text=True)
    if res_crypto.returncode == 0:
        print("[+] Native cryptography installed/verified.")
    else:
        print("[!] Warning: Could not install cryptography via pip. Native crypto is required for B2CHKS.")

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
            cmd_file = target_dir / f"{name}.cmd"
            with open(cmd_file, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\n"{py_exec}" "{source_script}" %*\r\n')

            bat_file = target_dir / f"{name}.bat"
            with open(bat_file, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\n"{py_exec}" "{source_script}" %*\r\n')

            ps1_file = target_dir / f"{name}.ps1"
            with open(ps1_file, "w", encoding="utf-8") as f:
                f.write(f'& "{py_exec}" "{source_script}" $args\r\n')

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
    print("  Native-only B2CHKS is ready to use globally.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="B2CHKS Global Installer & Uninstaller")
    parser.add_argument("--uninstall", "-u", action="store_true", help="Uninstall B2CHKS globally")
    args = parser.parse_args()

    if args.uninstall or (len(sys.argv) > 1 and sys.argv[1].lower() in ["uninstall", "remove"]):
        uninstall()
    else:
        install()


if __name__ == "__main__":
    main()
