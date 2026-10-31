"""BBT - Bug Bounty Toolkit.

A cross-platform, modular security assessment toolkit for testers who need to
assess assets on an internal/local network first and public/hosted sites after.

The package is intentionally dependency-light: only ``requests`` is required.
External tools (nmap, subfinder, whois, dig) are detected and used optionally
when they are present. In v2.2 the web module also crawls same-origin pages and
runs WordPress, SSRF and BOLA/IDOR checks; the report correlates findings into
attack paths.
"""

__version__ = "2.2.0"
__author__ = "AmirHossein Zarei (A-z-exe)"

__all__ = ["__version__", "__author__"]
