#!/usr/bin/env python3
"""Convenient standalone uninstaller for B2CHKS."""
import sys
import install

if __name__ == "__main__":
    ok = install.uninstall()
    sys.exit(0 if ok else 1)
