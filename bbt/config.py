"""Runtime configuration for the toolkit.

All tunables live here so modules never hard-code timeouts, paths or limits.
The CLI builds a :class:`Config` from parsed arguments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

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
    user_agent: str = "BBT/2.0 (+https://github.com/A-z-exe/BugBountyToolkit)"
    verify_tls: bool = False  # internal sites frequently use self-signed certs
    follow_redirects: bool = True
    proxy: Optional[str] = None

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
