#!/usr/bin/env python3
"""BugBountyToolkit entry point.

This thin wrapper keeps the historical ``bugbounty_tool.py`` name working while
the implementation lives in the :mod:`bbt` package.

Usage:
    python bugbounty_tool.py -t https://example.com -m full
    python bugbounty_tool.py -t 192.168.1.0/24 -m network
    python bugbounty_tool.py                      # interactive mode
"""
from bbt.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
