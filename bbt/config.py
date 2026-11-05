"""Runtime configuration for the toolkit.

All tunables live here so modules never hard-code timeouts, paths or limits.
The CLI builds a :class:`Config` from parsed arguments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .utils import DEFAULT_DIR_WORDS, DEFAULT_WEB_PATHS, TOP_PORTS

#: Modes accepted on the command line and in the interactive menu.
MODES = ("info", "network", "web", "api", "injection", "full")

#: Ports that are commonly dangerous when exposed without proper controls.
RISKY_PORTS = {
    21: "FTP - often allows anonymous access; plaintext credentials",
    23: "Telnet - plaintext remote shell",
    25: "SMTP - open relay / user enumeration",
    111: "rpcbind - can leak services, amplify DDoS",
    135: "MSRPC - Windows RPC, frequently abused",
    139: "NetBIOS - legacy SMB discovery",
    445: "SMB - ransomware / SMBGhost, null sessions",
    1433: "MSSQL - exposed database, brute force",
    1521: "Oracle - exposed database",
    2375: "Docker API (plaintext) - full host takeover",
    2376: "Docker API (TLS) - container control plane; verify mutual auth",
    3306: "MySQL - exposed database",
    3389: "RDP - brute force / BlueKeep",
    5432: "PostgreSQL - exposed database",
    5900: "VNC - often weak or no authentication",
    6379: "Redis - usually unauthenticated, RCE potential",
    9200: "Elasticsearch - open by default",
    11211: "Memcached - amplification, data exposure",
    27017: "MongoDB - often unauthenticated",
}


@dataclass
class Config:
    """Everything the scanner needs to know before it starts."""

    # Networking / HTTP behaviour
    timeout: float = 15.0
    connect_timeout: float = 3.0
    command_timeout: int = 300
    threads: int = 64
    rate: float = 30.0  # requests per second (0 disables throttling)
    user_agent: str = field(
        default_factory=lambda: (
            f"BBT/{__version__} (+https://github.com/A-z-exe/BugBountyToolkit)"
        )
    )
    verify_tls: bool = True  # disable with --insecure for self-signed internal sites
    follow_redirects: bool = True
    max_redirects: int = 10  # per request; hops are pinned to the same site
    proxy: Optional[str] = None
    #: Extra headers applied to every request (authentication, custom UA, ...).
    headers: Dict[str, str] = field(default_factory=dict)
    #: Cookies parsed from ``--cookie name=value``.
    cookies: Dict[str, str] = field(default_factory=dict)
    #: Second account, used for BOLA/IDOR comparison.
    headers_b: Dict[str, str] = field(default_factory=dict)
    cookies_b: Dict[str, str] = field(default_factory=dict)
    authz_ids: List[str] = field(default_factory=list)
    max_authz_urls: int = 15

    # Scope / target discovery
    scope: str = "auto"  # auto | local | remote
    max_hosts: int = 1024
    scan_network: bool = False  # also TCP-scan the resolved host of URL targets

    # Port scanning
    ports: Optional[str] = None  # e.g. "22,80,443,8000-8100"; None -> top ports
    use_optional_tools: bool = True  # use nmap/nikto/... when installed

    # Web content discovery
    wordlist: Optional[str] = None  # path to a custom wordlist (one word/line)
    web_paths: List[str] = field(default_factory=lambda: list(DEFAULT_WEB_PATHS))
    dir_words: List[str] = field(default_factory=lambda: list(DEFAULT_DIR_WORDS))
    max_paths: int = 400

    # Same-origin crawling (feeds parameter discovery / injection tests)
    max_pages: int = 25  # 0 disables crawling
    crawl_depth: int = 2
    max_injection_urls: int = 10
    max_injection_params: int = 6

    # SSRF probing (opt-in: --ssrf or --ssrf-url)
    ssrf_enabled: bool = False
    ssrf_callback: Optional[str] = None
    max_ssrf_urls: int = 10

    # Recon / reporting
    subdomain_enum: bool = False
    max_subdomains: int = 200
    extract_js: bool = True
    bounty_reports: bool = True
    write_pocs: bool = False
    authorized_pocs: bool = False

    # Safety
    aggressive: bool = False  # enables intrusive payloads (SQLi time-based, etc.)

    # API testing
    tokens: List[str] = field(default_factory=list)  # JWT/bearer tokens to analyse

    # Output / UI
    output_root: Path = field(default_factory=lambda: Path("results"))
    no_color: bool = False
    verbose: bool = False

    def __post_init__(self) -> None:
        self.output_root = Path(self.output_root)
        if not self.ports:
            self.ports = ",".join(str(p) for p in TOP_PORTS)
        # Keep the tuning knobs in a sane range even if the CLI passes junk.
        self.threads = max(1, int(self.threads))
        self.max_hosts = max(1, int(self.max_hosts))
        self.max_paths = max(0, int(self.max_paths))
        self.max_pages = max(0, int(self.max_pages))
        self.crawl_depth = max(1, int(self.crawl_depth))
        self.max_redirects = max(1, int(self.max_redirects))
        self.max_injection_urls = max(0, int(self.max_injection_urls))
        self.max_injection_params = max(0, int(self.max_injection_params))
        self.max_authz_urls = max(0, int(self.max_authz_urls))
        self.max_ssrf_urls = max(0, int(self.max_ssrf_urls))
        self.max_subdomains = max(1, int(self.max_subdomains))
        if self.rate is not None and self.rate < 0:
            self.rate = 0.0
