#!/usr/bin/env python3
"""Launcher: python winwitness_cli.py <evidence folder> -o <output folder> [options]

Works with `python -I` (isolated mode) because it adds its own folder explicitly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from camtool.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
