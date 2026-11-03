#!/usr/bin/env python3
"""
Installer script to install B2CHKS globally on any system (Linux, macOS, Windows).
"""

import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path


def install():
    print("[*] Installing B2CHKS globally...")
    repo_root = Path(__file__).parent.resolve()
    source_script = repo_root / "b2chks.py"

    if not source_script.exists():
        print("[-] Error: b2chks.py not found in source directory.")
        sys.exit(1)

    # 1. Try pip editable/global install first
    try:
        res = subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(repo_root)], capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Successfully installed B2CHKS via pip entrypoints (b2chks, core, chunkcore).")
            return
    except Exception as e:
        print(f"[*] Notice: pip install returned: {e}")

    # 2. Direct binary copy to user's binary PATH
    is_windows = platform.system() == "Windows"
    target_dirs = []

    if is_windows:
        user_local = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        target_dirs.append(Path(user_local) / "Microsoft" / "WindowsApps")
        target_dirs.append(Path(sys.prefix) / "Scripts")
    else:
        target_dirs.append(Path.home() / ".local" / "bin")
        target_dirs.append(Path("/usr/local/bin"))

    installed_dir = None
    for d in target_dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
            installed_dir = d
            break
        except Exception:
            continue

    if not installed_dir:
        print("[-] Could not find a writable directory in PATH. Please run with elevated permissions or pip install .")
        sys.exit(1)

    target_cmd = installed_dir / ("b2chks.exe" if is_windows else "b2chks")
    if is_windows:
        # Create a batch launcher on Windows
        bat_file = installed_dir / "b2chks.bat"
        with open(bat_file, "w", encoding="utf-8") as f:
            f.write(f'@echo off\n"{sys.executable}" "{source_script}" %*\n')
        print(f"[+] Installed Windows launcher: {bat_file}")
    else:
        shutil.copyfile(source_script, target_cmd)
        target_cmd.chmod(target_cmd.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        print(f"[+] Installed executable: {target_cmd}")

        # Also create 'core' alias
        core_cmd = installed_dir / "core"
        try:
            shutil.copyfile(source_script, core_cmd)
            core_cmd.chmod(core_cmd.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            print(f"[+] Installed alias: {core_cmd}")
        except Exception:
            pass

    print(f"\n[+] B2CHKS installed successfully to {installed_dir}!")
    print("    You can now run 'b2chks' or 'core' directly from any terminal window.")


if __name__ == "__main__":
    install()
