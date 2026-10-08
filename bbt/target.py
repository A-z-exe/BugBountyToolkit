"""Target parsing and classification.

Supports the four shapes a tester actually types:

* ``https://app.internal.corp:8443/login`` -> web target
* ``10.0.0.0/24``                          -> network range
* ``192.168.1.10:8080``                    -> host + port
* ``app.internal.corp``                    -> host (scheme assumed)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urlunparse

from .utils import expand_cidr, is_ip, is_private_ip

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_\-.]{0,252}[A-Za-z0-9_])?$")


@dataclass
class Target:
    raw: str
    kind: str = "url"  # url | host | ip | cidr
    scheme: str = "https"
    host: str = ""
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    display: str = ""
    is_private: bool = False

    # ------------------------------------------------------------------
    @property
    def is_network(self) -> bool:
        """True when this target should go through the network modules."""
        return self.kind in ("ip", "cidr", "host")

    @property
    def is_range(self) -> bool:
        return self.kind == "cidr"

    @property
    def default_port(self) -> int:
        if self.port:
            return self.port
        return 443 if self.scheme == "https" else 80

    @property
    def authority(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def base_url(self) -> str:
        netloc = self.host
        if self.port and not (
            (self.scheme == "http" and self.port == 80)
            or (self.scheme == "https" and self.port == 443)
        ):
            netloc = f"{self.host}:{self.port}"
        if ":" in self.host and not self.host.startswith("["):  # bare IPv6
            netloc = f"[{self.host}]" + (f":{self.port}" if self.port else "")
        return urlunparse((self.scheme, netloc, self.path or "/", "", "", ""))

    @property
    def url_with_query(self) -> str:
        """Base URL including the original query string, if any."""
        return f"{self.base_url}?{self.query}" if self.query else self.base_url

    @property
    def origin(self) -> str:
        netloc = self.host
        if self.port:
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"

    def hosts(self, max_hosts: int = 1024) -> List[str]:
        """Return the list of host addresses/IPs this target represents."""
        if self.kind == "cidr":
            return expand_cidr(self.raw, max_hosts=max_hosts)
        return [self.host]

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "kind": self.kind,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "is_private": self.is_private,
        }


def _valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    # Allow IPv6 literals handled elsewhere; here only names/IPv4.
    if " " in host or "\\" in host or "/" in host:
        return False
    return bool(is_ip(host) or _HOSTNAME_RE.match(host))


def parse_target(value: str, default_scheme: str = "https") -> Target:
    """Parse a user supplied target into a :class:`Target`.

    Raises :class:`ValueError` if the input cannot be interpreted.
    """
    if not value or not value.strip():
        raise ValueError("empty target")
    raw = value.strip()

    # --- Explicit URL -------------------------------------------------
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {parsed.scheme!r}")
        host = parsed.hostname or ""
        if not host:
            raise ValueError(f"could not parse host from: {raw}")
        try:
            port = parsed.port
        except ValueError:
            raise ValueError(f"invalid port in: {raw}")
        path = parsed.path or "/"
        display = raw
        return Target(
            raw=raw,
            kind="url",
            scheme=parsed.scheme,
            host=host,
            port=port,
            path=path,
            query=parsed.query,
            display=display,
            is_private=is_private_ip(host),
        )

    # --- CIDR / network range ----------------------------------------
    if "/" in raw and not raw.startswith("["):
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return Target(
                raw=raw,
                kind="cidr",
                host=str(net.network_address),
                display=raw,
                is_private=net.is_private or net.is_loopback,
            )
        except ValueError:
            # Not a network; fall through (e.g. "example.com/path").
            pass

    # --- host[:port] --------------------------------------------------
    host = raw
    port: Optional[int] = None
    if raw.startswith("["):
        # IPv6 literal, optionally with :port
        end = raw.find("]")
        if end == -1:
            raise ValueError(f"invalid IPv6 target: {raw}")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest.startswith(":"):
            port = int(rest[1:]) if rest[1:].isdigit() else None
    elif raw.count(":") == 1:
        candidate_host, _, candidate_port = raw.partition(":")
        if candidate_port.isdigit():
            host, port = candidate_host, int(candidate_port)
    elif raw.count(":") > 1 and not is_ip(raw):
        # Multiple colons but not a valid IP -> probably host/path.
        host, _, _path = raw.partition("/")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")
    if not _valid_hostname(host):
        raise ValueError(f"invalid host: {host!r}")

    kind = "ip" if is_ip(host) else "host"
    # A bare hostname without a port is ambiguous; treat as a web target on the
    # default scheme so the web modules can do useful work, but keep the network
    # semantics available through ``kind``.
    return Target(
        raw=raw,
        kind=kind,
        scheme=default_scheme,
        host=host,
        port=port,
        path="/",
        display=raw,
        is_private=is_private_ip(host),
    )


def parse_many(values: List[str], default_scheme: str = "https") -> List[Target]:
    """Parse a list of raw targets, skipping (and reporting) invalid ones."""
    targets: List[Target] = []
    for value in values:
        if not value.strip() or value.strip().startswith("#"):
            continue
        try:
            targets.append(parse_target(value, default_scheme=default_scheme))
        except ValueError as exc:
            raise ValueError(f"{value!r}: {exc}")
    return targets


def load_targets_file(path: str, default_scheme: str = "https") -> List[str]:
    """Read a targets file (one target per line, ``#`` comments allowed)."""
    raw_lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                raw_lines.append(line)
    return raw_lines
