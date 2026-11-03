#!/usr/bin/env python3
"""
B2CHKS: High-performance file packaging, chunking, compression, and distribution protocol.
Top-level entrypoint and compatibility wrapper forwarding to cli.main.
"""
import sys
from cli.main import main
import b2chks
from b2chks import *

if __name__ == "__main__":
    main()
