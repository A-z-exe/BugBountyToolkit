"""Terminal output helpers and logging setup."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GREY = "\033[90m"

_SEVERITY_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}


def _enable_windows_ansi() -> bool:
    """Enable VT processing on classic Windows consoles (best effort)."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(
            kernel32.SetConsoleMode(
                handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            )
        )
    except Exception:
        return False


def supports_color(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if os.name == "nt" and stream is sys.stdout:
        return _enable_windows_ansi()
    return True


class UI:
    """Minimal, dependency-free console reporter."""

    def __init__(self, color: bool = True) -> None:
        self.color = bool(color) and supports_color()

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def say(self, text: str = "") -> None:
        print(text)

    def info(self, text: str) -> None:
        print(f"{self._c(CYAN, '[*]')} {text}")

    def ok(self, text: str) -> None:
        print(f"{self._c(GREEN, '[+]')} {text}")

    def warn(self, text: str) -> None:
        print(f"{self._c(YELLOW, '[!]')} {text}")

    def error(self, text: str) -> None:
        print(f"{self._c(RED, '[-]')} {text}")

    def found(self, severity: str, title: str, target: str = "") -> None:
        color = _SEVERITY_COLOR.get(severity, GREY)
        tag = self._c(color, f"[{severity.upper()}]")
        suffix = f" {self._c(GREY, '(' + target + ')')}" if target else ""
        print(f"{tag} {title}{suffix}")

    def header(self, text: str) -> None:
        line = "=" * 60
        print(self._c(BOLD, line))
        print(self._c(BOLD, text))
        print(self._c(BOLD, line))


def setup_logging(
    verbose: bool = False, logfile: Optional[Path] = None
) -> logging.Logger:
    """Configure the ``bbt`` logger.

    Console output stays quiet (WARNING) unless ``verbose`` is set; the file
    handler always records DEBUG so we can debug a run after the fact.
    """
    logger = logging.getLogger("bbt")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("%(levelname)-7s %(name)s: %(message)s"))
    logger.addHandler(console)

    if logfile is not None:
        logfile = Path(logfile)
        logfile.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(logfile, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)

    return logger


BANNER = r"""
    ____  ____ ______
   / __ )/ __ )_  __/     Advanced Security Assessment Toolkit
  / __  / __  |/ /       for internal networks and web applications
 / /_/ / /_/ / / /
/_____/\____/ /_/        v{version}  -  github.com/A-z-exe
"""


def print_banner() -> None:
    print(BANNER.format(version=__version__))
