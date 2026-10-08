"""Command line interface and interactive mode."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .config import MODES, Config
from .core import Scanner
from .target import Target, load_targets_file, parse_target
from .ui import UI, print_banner, setup_logging
from .utils import have_tool, platform_name, python_ok

OPTIONAL_TOOLS = {
    "nmap": "service/version detection during network scans",
    "nikto": "additional web server checks",
    "subfinder": "passive subdomain discovery",
    "whois": "domain registration data",
    "dig": "detailed DNS records",
    "sqlmap": "advanced SQL injection testing (manual, optional)",
}

LEGAL_TEXT = """
LEGAL DISCLAIMER AND USAGE AGREEMENT
------------------------------------
This tool is intended for:
  - Testing systems you own or operate
  - Authorized penetration tests with written permission
  - Bug bounty programs within their declared scope
  - Education in controlled lab environments

DO NOT use it against systems without explicit authorization.
Unauthorized access to computer systems is illegal in most jurisdictions.
You are solely responsible for complying with applicable laws.
"""


def check_tools(ui: UI) -> bool:
    ui.header("Optional external tools")
    all_present = True
    for tool, purpose in OPTIONAL_TOOLS.items():
        if have_tool(tool):
            ui.ok(f"{tool:<12} installed   - {purpose}")
        else:
            all_present = False
            ui.warn(f"{tool:<12} not found   - {purpose}")
    if not all_present:
        ui.info(
            "The toolkit works fully in pure Python; these tools only add extra depth."
        )
    return all_present


def validate_legal(ui: UI) -> None:
    print(LEGAL_TEXT)
    while True:
        answer = input("Do you agree to use this tool only for authorized testing? (yes/no): ").strip().lower()
        if answer in ("yes", "y"):
            return
        if answer in ("no", "n"):
            ui.error("Authorization not confirmed. Exiting.")
            raise SystemExit(1)
        ui.warn("Please answer 'yes' or 'no'.")


def build_config(args: argparse.Namespace) -> Config:
    return Config(
        timeout=args.timeout,
        connect_timeout=args.connect_timeout,
        command_timeout=args.command_timeout,
        threads=args.threads,
        rate=args.rate,
        verify_tls=args.verify_tls,
        proxy=args.proxy,
        scope=args.scope,
        max_hosts=args.max_hosts,
        scan_network=args.scan_network,
        ports=args.ports,
        use_optional_tools=not args.no_optional_tools,
        wordlist=args.wordlist,
        max_paths=args.max_paths,
        aggressive=args.aggressive,
        output_root=Path(args.output),
        no_color=args.no_color,
        verbose=args.verbose,
        tokens=list(args.jwt or []),
    )


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bugbounty_tool.py",
        description="Cross-platform security assessment for internal networks and web apps.",
        epilog="Example: python bugbounty_tool.py -t https://example.com -m full",
    )
    parser.add_argument("-t", "--target", action="append", default=[],
                        help="Target: URL, host, IP or CIDR. Repeatable.")
    parser.add_argument("-f", "--targets-file",
                        help="File with one target per line ('#' comments allowed).")
    parser.add_argument("-m", "--mode", choices=list(MODES),
                        help="Scan mode: " + ", ".join(MODES))
    parser.add_argument("--scope", choices=["auto", "local", "remote"], default="auto",
                        help="Restrict/order targets: local first when 'auto'.")
    parser.add_argument("--scan-network", action="store_true",
                        help="Also TCP-scan the host behind each URL target.")
    parser.add_argument("--ports", help="Port spec, e.g. '22,80,443,8000-8100'.")
    parser.add_argument("--threads", type=int, default=64, help="Worker threads (default 64).")
    parser.add_argument("--rate", type=float, default=30.0, help="HTTP requests/second (0 = unlimited).")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds.")
    parser.add_argument("--connect-timeout", type=float, default=3.0, help="TCP connect timeout in seconds.")
    parser.add_argument("--command-timeout", type=int, default=300, help="Timeout for external tools.")
    parser.add_argument("--wordlist", help="Custom wordlist for content discovery.")
    parser.add_argument("--max-paths", type=int, default=400, help="Max paths to probe per target.")
    parser.add_argument("--max-hosts", type=int, default=1024, help="Max hosts to expand from a CIDR.")
    parser.add_argument("--jwt", action="append", help="JWT/bearer token to analyse. Repeatable.")
    parser.add_argument("--proxy", help="Proxy URL for HTTP(S) requests.")
    parser.add_argument("--verify-tls", action="store_true", help="Verify TLS certificates (default: off).")
    parser.add_argument("--no-optional-tools", action="store_true",
                        help="Never call external tools even if installed.")
    parser.add_argument("--aggressive", action="store_true",
                        help="Enable intrusive checks (time-based SQLi).")
    parser.add_argument("-o", "--output", default="results", help="Output root directory.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    parser.add_argument("--skip-legal", action="store_true",
                        help="Skip the legal disclaimer (authorized use only).")
    parser.add_argument("--version", action="version", version=f"BBT {__version__}")
    return parser.parse_args(argv)


def _prompt_targets(ui: UI, existing: List[Target]) -> List[Target]:
    raw = input("Enter target(s) (comma or space separated): ").strip()
    if not raw:
        return existing
    parts = [p for p in raw.replace(",", " ").split() if p]
    targets: List[Target] = []
    for part in parts:
        try:
            targets.append(parse_target(part))
        except ValueError as exc:
            ui.warn(f"Invalid target {part!r}: {exc}")
    return targets or existing


def interactive(config: Config, ui: UI, logger) -> int:
    scanner = Scanner(config, ui, logger)
    targets: List[Target] = []

    menu = (
        "\n" + "=" * 60 + "\n"
        "  BBT - Security Assessment Menu\n" + "=" * 60 + "\n"
        "  1. Information gathering (DNS/WHOIS/TLS)\n"
        "  2. Network scan (ports/services)\n"
        "  3. Web assessment\n"
        "  4. API review\n"
        "  5. Injection checks\n"
        "  6. Full scan (local assets first, then remote)\n"
        "  7. Check optional tools\n"
        "  8. Exit\n" + "=" * 60
    )
    mode_map = {"1": "info", "2": "network", "3": "web", "4": "api",
                "5": "injection", "6": "full"}

    while True:
        print(menu)
        if targets:
            ui.info("Targets: " + ", ".join(t.display for t in targets))
        else:
            ui.warn("No targets set yet (choose a scan to enter them).")
        choice = input("Choose an option: ").strip()

        if choice == "8":
            ui.ok("Goodbye. Only test systems you are authorized to test.")
            return 0
        if choice == "7":
            check_tools(ui)
            continue
        if choice not in mode_map:
            ui.warn("Invalid choice.")
            continue

        targets = _prompt_targets(ui, targets)
        if not targets:
            ui.warn("No valid targets provided.")
            continue
        try:
            scanner.scan(targets, mode_map[choice])
        except ValueError as exc:
            ui.error(str(exc))
        except KeyboardInterrupt:
            ui.warn("Interrupted.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)
    ui = UI(color=not args.no_color)
    print_banner()

    if not python_ok():
        ui.error("Python 3.8 or newer is required.")
        return 2

    try:
        import requests  # noqa: F401
    except ImportError:
        ui.error("The 'requests' package is required. Install it with: pip install -r requirements.txt")
        return 2

    if not (args.skip_legal or os.environ.get("BBT_SKIP_LEGAL")):
        validate_legal(ui)

    config = build_config(args)
    config.output_root.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(verbose=args.verbose, logfile=config.output_root / "bbt.log")
    logger.info("BBT %s on %s", __version__, platform_name())

    # Collect targets from CLI and/or file.
    raw_targets: List[str] = list(args.target or [])
    if args.targets_file:
        try:
            raw_targets.extend(load_targets_file(args.targets_file))
        except OSError as exc:
            ui.error(f"Could not read targets file: {exc}")
            return 2

    targets: List[Target] = []
    for value in raw_targets:
        try:
            targets.append(parse_target(value))
        except ValueError as exc:
            ui.error(f"Invalid target {value!r}: {exc}")
            return 2

    if args.mode:
        if not targets:
            ui.error("A target is required. Use -t/--target or -f/--targets-file.")
            return 2
        scanner = Scanner(config, ui, logger)
        try:
            session_dir = scanner.scan(targets, args.mode)
        except ValueError as exc:
            ui.error(str(exc))
            return 2
        except KeyboardInterrupt:
            ui.warn("Scan interrupted by user.")
            return 130
        ui.ok(f"Done. Reports are in: {session_dir}")
        return 0

    try:
        return interactive(config, ui, logger)
    except KeyboardInterrupt:
        ui.warn("Interrupted by user.")
        return 130
