#!/usr/bin/env python3
"""
main.py
=======
Top-level entry point for LogSentinel.
Run `python main.py --help` to see all available options.
"""

import sys

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())