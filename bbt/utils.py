"""Low level helpers: subprocess, tool discovery, sockets and small utilities.

Nothing in this module imports from other ``bbt`` modules, which keeps it safe
to import from everywhere (including ``config``).
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# Port / service knowledge
# ---------------------------------------------------------------------------

SERVICE_NAMES: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "http-alt",
    3306: "mysql",
    3389: "ms-wbt-server",
    5000: "http-alt",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    6379: "redis",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
}

#: A pragmatic "top ports" list that covers both typical web stacks and the
#: services that show up on internal networks.
TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 636, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389,
    5000, 5432, 5601, 5900, 6379, 7001, 8000, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 11211, 27017, 27018,
]

HTTP_PORTS = (80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000, 9090)
HTTPS_PORTS = (443, 8443)
#: Ports probed during host discovery on a CIDR range. Kept small on purpose.
DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 8080, 8443)

DEFAULT_WEB_PATHS: List[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.svn/entries",
    "/.htaccess",
    "/.htpasswd",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/phpmyadmin/",
    "/admin/",
    "/adminer.php",
    "/wp-login.php",
    "/wp-admin/",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/console",
    "/debug",
    "/.DS_Store",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/web.config",
    "/WEB-INF/web.xml",
]

DEFAULT_DIR_WORDS: List[str] = [
    "admin", "administrator", "login", "logout", "dashboard", "portal",
    "backup", "backups", "bak", "old", "new", "test", "testing", "dev",
    "staging", "stage", "uat", "prod", "production", "config", "conf",
    "settings", "setup", "install", "installer", "db", "database", "sql",
    "private", "secret", "secrets", "internal", "intranet", "api", "apis",
    "v1", "v2", "v3", "graphql", "swagger", "docs", "documentation",
    "assets", "static", "media", "uploads", "files", "download", "downloads",
    "images", "img", "css", "js", "scripts", "includes", "inc", "tmp",
    "temp", "cache", "logs", "log", "error", "errors", "status", "health",
    "metrics", "monitor", "debug", "trace", "phpinfo", "info", "readme",
    "README", "license", "LICENSE", "changelog", "CHANGELOG", "users",
    "user", "accounts", "account", "profile", "profiles", "register",
    "signup", "signin", "auth", "oauth", "sso", "saml", "token", "tokens",
    "keys", "key", "cert", "certs", "backup.sql", "dump.sql", "database.sql",
    "web.config", "app.config", ".git", ".svn", ".env", ".htaccess",
]

# ---------------------------------------------------------------------------
# Filesystem / naming
# ---------------------------------------------------------------------------

_SAFE_RE = re.compile(r"[^\w\-.]+")


def safe_filename(value: str, fallback: str = "target") -> str:
    """Turn arbitrary text into a filesystem-safe single path component."""
    value = (value or "").strip()
    value = value.replace("://", "_")
    value = _SAFE_RE.sub("_", value)
    value = value.strip("._") or fallback
    return value[:120]


def now_stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------------
# External tool discovery / execution
# ---------------------------------------------------------------------------


def which(name: str) -> Optional[str]:
    """Cross-platform ``which`` (``shutil.which`` already handles Windows)."""
    return shutil.which(name)


def have_tool(name: str) -> bool:
    return which(name) is not None


def run_command(
    args: Sequence[str],
    timeout: int = 30,
    output_file: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    """Run a command *without a shell* and capture its result.

    Returns a dict with ``returncode``, ``stdout``, ``stderr`` and
    ``output_file``. Missing binaries yield ``returncode == 127`` and timeout
    yields ``returncode == -1`` so callers never need to guard for exceptions.
    """
    args = [str(a) for a in args]
    if output_file is not None:
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        if output_file is not None:
            with open(output_file, "w", encoding="utf-8", errors="replace") as fh:
                proc = subprocess.run(
                    args,
                    stdout=fh,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                    env=env,
                )
            return {
                "returncode": proc.returncode,
                "stdout": "",
                "stderr": proc.stderr or "",
                "output_file": str(output_file),
            }
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "output_file": None,
        }
    except FileNotFoundError:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": f"command not found: {args[0]}",
            "output_file": str(output_file) if output_file else None,
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"timed out after {timeout}s: {' '.join(args)}",
            "output_file": str(output_file) if output_file else None,
        }
    except OSError as exc:  # pragma: no cover - platform specific
        return {
            "returncode": 126,
            "stdout": "",
            "stderr": f"OS error running {args[0]}: {exc}",
            "output_file": str(output_file) if output_file else None,
        }


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def expand_cidr(cidr: str, max_hosts: int = 1024) -> List[str]:
    """Expand a CIDR (or single IP) into a list of host addresses."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses == 1:
        return [str(net.network_address)]
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > max_hosts:
        raise ValueError(
            f"{cidr} expands to {len(hosts)} hosts, above the limit of {max_hosts}. "
            "Increase --max-hosts or narrow the range."
        )
    return hosts


def parse_ports(spec: Optional[str], default: Optional[Iterable[int]] = None) -> List[int]:
    """Parse ``"22,80,8000-8010"`` into a sorted list of valid ports."""
    ports = set()
    if spec:
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start, _, end = chunk.partition("-")
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                if end - start > 65535:
                    raise ValueError(f"invalid port range: {chunk}")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(chunk))
    elif default:
        ports.update(int(p) for p in default)
    return sorted(p for p in ports if 1 <= p <= 65535)


def service_name(port: int) -> str:
    return SERVICE_NAMES.get(port, "unknown")


# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------


def scan_tcp_port(
    host: str, port: int, timeout: float = 3.0, banner: bool = True
) -> Tuple[bool, str]:
    """Connect-scan a single TCP port and optionally grab a banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            text = ""
            if banner:
                try:
                    sock.settimeout(min(2.0, max(0.5, timeout)))
                    if port in HTTP_PORTS:
                        sock.sendall(
                            b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                        )
                    chunk = sock.recv(256)
                    text = chunk.decode("latin-1", "ignore").strip()
                except (socket.timeout, OSError):
                    text = ""
            return True, text
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
        return False, ""


def resolve_host(host: str) -> List[str]:
    """Resolve a hostname to a de-duplicated list of IP addresses."""
    results: List[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return results
    for info in infos:
        addr = info[4][0]
        if addr not in results:
            results.append(addr)
    return results


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe token-ish limiter expressed as requests per second."""

    def __init__(self, per_second: float) -> None:
        self.min_interval = 1.0 / per_second if per_second and per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.min_interval
            delay = start - now
        if delay > 0:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def platform_name() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def python_ok() -> bool:
    return sys.version_info >= (3, 8)
