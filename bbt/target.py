"""Target parsing and classification.

Supports the shapes a tester actually types:

* ``https://app.internal.corp:8443/login`` -> web target
* ``10.0.0.0/24``                          -> network range
* ``192.168.1.10:8080``                    -> host + port
* ``app.internal.corp``                    -> host (scheme assumed)
* ``192.168.1.10:8080/admin?x=1``          -> host + port + path
* ``[::1]:8443``                           -> IPv6 host + port
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, urlunparse

from .utils import expand_cidr, is_ip, is_private_ip

_Hostname_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_\-.]{0,252}[A-Za-z0-9_])?$")

#: Ports where TLS is attempted when the target does not name a scheme.
_TLS_PORTS = (443, 8443, 9443)


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
    #: True when the user typed the scheme themselves (http://...).
    explicit_scheme: bool = False

    # ------------------------------------------------------------------
    @property
    def is_network(self) -> bool:
        """True when this target should go through the network module."""
        return self.kind in ("ip", "cidr", "host")

    @property
    def is_web(self) -> bool:
        """True when an HTTP(S) service is expected on this target."""
        return self.kind in ("url", "host", "ip")

    @property
    def is_range(self) -> bool:
        return self.kind == "cidr"

    @property
    def default_port(self) -> int:
        if self.port:
            return self.port
        return 443 if self.scheme == "https" else 80

    @property
    def bracketed_host(self) -> str:
        """Host in URL form (IPv6 addresses get brackets)."""
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def authority(self) -> str:
        """Host with an explicit port when one was provided."""
        if self.port:
            return f"{self.bracketed_host}:{self.port}"
        return self.bracketed_host

    @property
    def netloc(self) -> str:
        """Host/port for a URL, omitting the scheme's default port."""
        if self.port and not (
            (self.scheme == "http" and self.port == 80)
            or (self.scheme == "https" and self.port == 443)
        ):
            return f"{self.bracketed_host}:{self.port}"
        return self.bracketed_host

    @property
    def base_url(self) -> str:
        return urlunparse((self.scheme, self.netloc, self.path or "/", "", "", ""))

    @property
    def url_with_query(self) -> str:
        """Base URL including the original query string, if any."""
        return f"{self.base_url}?{self.query}" if self.query else self.base_url

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def web_schemes(self) -> List[str]:
        """Schemes to try when no scheme was given explicitly.

        HTTPS is preferred; plain HTTP is still tried so internal or legacy
        services are not silently skipped.
        """
        if self.explicit_scheme or self.kind == "url":
            return [self.scheme]
        return ["https", "http"]

    @property
    def is_tls_likely(self) -> bool:
        """Whether a TLS handshake is worth attempting on this target."""
        if self.explicit_scheme or self.kind == "url":
            return self.scheme == "https"
        if self.port:
            return self.port in _TLS_PORTS
        return True  # bare hostname -> assume 443 may speak TLS

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
            "explicit_scheme": self.explicit_scheme,
        }


def _valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    # Allow IPv6 literals handled elsewhere; here only names/IPv4.
    if " " in host or "\\" in host or "/" in host:
        return False
    return bool(is_ip(host) or _Hostname_RE.match(host))


def _split_path_query(tail: str) -> tuple:
    path_part, _, query = tail.partition("?")
    path = "/" + path_part.lstrip("/") if path_part else "/"
    return path, query


def parse_target(value: str, default_scheme: str = "https") -> Target:
    """Parse a user supplied target into a :class:`Target`.

    Raises :class:`ValueError` if the input cannot be interpreted.
    """
    if not value or not value.strip():
        raise ValueError("empty target")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("target contains control characters")
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
            raise ValueError(f"invalid port in: {raw}") from None
        return Target(
            raw=raw,
            kind="url",
            scheme=parsed.scheme,
            host=host,
            port=port,
            path=parsed.path or "/",
            query=parsed.query,
            display=raw,
            is_private=is_private_ip(host),
            explicit_scheme=True,
        )

    # --- CIDR / network range ----------------------------------------
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return Target(
                raw=raw,
                kind="cidr",
                host=str(net.network_address),
                display=raw,
                is_private=bool(net.is_private or net.is_loopback),
            )
        except ValueError:
            # Not a network; fall through (e.g. "example.com/path").
            pass

    # --- host[:port][/path][?query] ----------------------------------
    path = "/"
    query = ""
    host = ""
    port: Optional[int] = None

    if raw.startswith("["):
        # IPv6 literal: [::1] or [::1]:8443[/path]
        end = raw.find("]")
        if end == -1:
            raise ValueError(f"invalid IPv6 target: {raw}")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest.startswith(":"):
            port_text, _, rest = rest[1:].partition("/")
            if port_text:
                if not port_text.isdigit():
                    raise ValueError(f"invalid port in: {raw}")
                port = int(port_text)
            if rest:
                path, query = _split_path_query(rest)
        elif rest.startswith("/"):
            path, query = _split_path_query(rest[1:])
    else:
        hostport, sep, tail = raw.partition("/")
        if sep:
            path, query = _split_path_query(tail)
        else:
            hostport, qsep, qtail = raw.partition("?")
            if qsep:
                query = qtail

        if is_ip(hostport):
            host = hostport
        elif hostport.count(":") == 1:
            candidate_host, _, candidate_port = hostport.partition(":")
            if candidate_port.isdigit():
                host, port = candidate_host, int(candidate_port)
            elif candidate_port == "":
                host = candidate_host
            else:
                raise ValueError(
                    f"invalid port {candidate_port!r} in target {raw!r}"
                )
        else:
            host = hostport

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
        path=path or "/",
        query=query,
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
            raise ValueError(f"{value!r}: {exc}") from None
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
