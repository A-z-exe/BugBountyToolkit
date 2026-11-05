"""Authorization scope enforcement for autonomous hunts.

A bug-bounty run is only legal for the assets the program lists. This module
turns a scope file (one entry per line) or ``--scope-host`` values into an
allow-list and refuses anything else. Entries are host/network based:

* ``example.com``      -> the apex and every subdomain
* ``*.example.com``    -> subdomains only
* ``https://app.example.com`` -> that exact host (optionally with a port)
* ``203.0.113.10``     -> that IP
* ``203.0.113.0/24``   -> that network

Private, loopback, link-local and cloud-metadata addresses are rejected while
resolving the target unless ``allow_private`` is set for an isolated lab.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from .target import Target
from .utils import is_ip, resolve_host

_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}


class ScopeError(ValueError):
    """Raised when a target or scope entry is invalid / not authorized."""


def _normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _valid_hostname(host: str) -> bool:
    host = _normalize_host(host)
    if not host or len(host) > 253:
        return False
    if host.startswith(".") or host.endswith("."):
        return False
    return all(_LABEL_RE.match(label) for label in host.split("."))


@dataclass(frozen=True)
class ScopeEntry:
    raw: str
    kind: str  # domain | wildcard | url | ip | cidr
    host: str = ""
    port: Optional[int] = None
    network: object = None  # ipaddress network for cidr entries

    def matches_host(self, host: str) -> bool:
        host = _normalize_host(host)
        if not host:
            return False
        if self.kind == "domain":
            return host == self.host or host.endswith("." + self.host)
        if self.kind == "wildcard":
            return host.endswith("." + self.host) and host != self.host
        if self.kind == "url":
            return host == self.host
        return False

    def matches_ip(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if self.kind == "ip":
            try:
                return address == ipaddress.ip_address(self.host)
            except ValueError:
                return False
        if self.kind == "cidr" and self.network is not None:
            try:
                return address in self.network  # type: ignore[operator]
            except TypeError:
                return False
        return False

    def matches_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = parsed.hostname or ""
        if not (self.matches_host(host) or self.matches_ip(host)):
            return False
        if self.kind == "url" and self.port is not None:
            return parsed.port == self.port
        return True


def parse_scope_entry(raw: str) -> ScopeEntry:
    value = (raw or "").strip()
    if not value:
        raise ScopeError("empty scope entry")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ScopeError(f"scope entry contains control characters: {raw!r}")
    if value in ("*", "*.*", "0.0.0.0/0", "::/0"):
        raise ScopeError("refusing an unrestricted scope entry")

    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            raise ScopeError(f"unsupported scope scheme: {parsed.scheme!r}")
        host = _normalize_host(parsed.hostname or "")
        if not (is_ip(host) or _valid_hostname(host)):
            raise ScopeError(f"invalid scope host: {host!r}")
        try:
            port = parsed.port
        except ValueError:
            raise ScopeError(f"invalid port in scope entry: {raw!r}") from None
        kind = "ip" if is_ip(host) else "url"
        return ScopeEntry(raw=value, kind=kind, host=host, port=port)

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None:
            if network.prefixlen == 0:
                raise ScopeError("refusing an unrestricted /0 scope entry")
            return ScopeEntry(raw=value, kind="cidr", host=str(network.network_address), network=network)
        # "example.com/path" is accepted as a URL for convenience.
        parsed = urlparse("https://" + value)
        host = _normalize_host(parsed.hostname or "")
        if not (is_ip(host) or _valid_hostname(host)):
            raise ScopeError(f"invalid scope entry: {raw!r}")
        return ScopeEntry(raw=value, kind="url", host=host, port=None)

    if value.startswith("*."):
        base = _normalize_host(value[2:])
        if not _valid_hostname(base):
            raise ScopeError(f"invalid wildcard scope entry: {raw!r}")
        return ScopeEntry(raw=value, kind="wildcard", host=base)

    if is_ip(value):
        return ScopeEntry(raw=value, kind="ip", host=_normalize_host(value))

    host = _normalize_host(value)
    if not _valid_hostname(host):
        raise ScopeError(f"invalid scope entry: {raw!r}")
    return ScopeEntry(raw=value, kind="domain", host=host)


class ScopePolicy:
    """An allow-list of hosts, URLs and networks."""

    def __init__(
        self,
        entries: Iterable[ScopeEntry] = (),
        allow_private: bool = False,
    ) -> None:
        self.entries: List[ScopeEntry] = list(entries)
        self.allow_private = bool(allow_private)

    # ------------------------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path, allow_private: bool = False) -> "ScopePolicy":
        entries: List[ScopeEntry] = []
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                entries.append(parse_scope_entry(line))
            except ScopeError as exc:
                raise ScopeError(f"{path}:{number}: {exc}") from None
        return cls(entries, allow_private=allow_private)

    @classmethod
    def from_entries(
        cls, values: Sequence[str], allow_private: bool = False
    ) -> "ScopePolicy":
        return cls([parse_scope_entry(value) for value in values], allow_private=allow_private)

    @classmethod
    def from_sources(
        cls,
        scope_file: Optional[str] = None,
        inline: Optional[Sequence[str]] = None,
        allow_private: bool = False,
    ) -> "ScopePolicy":
        entries: List[ScopeEntry] = []
        if scope_file:
            entries.extend(cls.from_file(scope_file, allow_private=allow_private).entries)
        for value in inline or []:
            entries.append(parse_scope_entry(value))
        return cls(entries, allow_private=allow_private)

    @classmethod
    def for_targets(cls, targets: Sequence[Target]) -> "ScopePolicy":
        """Exact-host scope used when the user did not supply a scope list."""
        entries: List[ScopeEntry] = []
        for target in targets:
            if target.kind == "cidr":
                entries.append(parse_scope_entry(target.raw))
            elif is_ip(target.host):
                entries.append(parse_scope_entry(target.host))
            elif target.kind == "url":
                entries.append(
                    ScopeEntry(raw=target.url_with_query, kind="url", host=_normalize_host(target.host))
                )
            else:
                entries.append(ScopeEntry(raw=target.host, kind="url", host=_normalize_host(target.host)))
        return cls(entries)

    # ------------------------------------------------------------------
    def allows_host(self, host: str) -> bool:
        return any(entry.matches_host(host) for entry in self.entries)

    def allows_ip(self, value: str) -> bool:
        return any(entry.matches_ip(value) for entry in self.entries)

    def allows_url(self, url: str) -> bool:
        return any(entry.matches_url(url) for entry in self.entries)

    def allows_target(self, target: Target) -> bool:
        if target.kind == "cidr":
            try:
                network = ipaddress.ip_network(target.raw, strict=False)
            except ValueError:
                return False
            for entry in self.entries:
                if entry.kind == "cidr" and entry.network is not None:
                    if network.version == entry.network.version and network.subnet_of(entry.network):
                        return True
            return False
        if target.kind == "url":
            return self.allows_url(target.url_with_query)
        return self.allows_host(target.host) or self.allows_ip(target.host)

    def supports_subdomains(self, host: str) -> bool:
        """True when the scope explicitly covers subdomains of ``host``."""
        host = _normalize_host(host)
        for entry in self.entries:
            if entry.kind in ("domain", "wildcard") and entry.matches_host(host):
                return True
        return False

    def assert_target(self, target: Target) -> None:
        if not self.allows_target(target):
            raise ScopeError(
                f"target {target.display!r} is outside the authorized scope "
                f"({self.describe() or 'empty scope'})"
            )

    def describe(self) -> str:
        return ", ".join(entry.raw for entry in self.entries)

    def to_list(self) -> List[str]:
        return [entry.raw for entry in self.entries]

    def __len__(self) -> int:
        return len(self.entries)


# ---------------------------------------------------------------------------
# Address safety
# ---------------------------------------------------------------------------


def target_addresses(target: Target) -> List[str]:
    if target.kind == "cidr":
        try:
            network = ipaddress.ip_network(target.raw, strict=False)
        except ValueError:
            return []
        return [str(network.network_address)]
    if is_ip(target.host):
        return [target.host]
    return resolve_host(target.host)


def guard_addresses(
    target: Target, allow_private: bool = False
) -> List[str]:
    """Resolve a target and reject non-public addresses.

    Returns the resolved address list so callers can log/pin it.
    """
    addresses = target_addresses(target)
    if not addresses:
        raise ScopeError(f"could not resolve {target.host!r}; refusing to scan")
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if str(address) in _METADATA_IPS or address.is_link_local:
            raise ScopeError(
                f"{target.display!r} resolves to a link-local/metadata address ({value}); refused"
            )
        if address.is_multicast or address.is_unspecified:
            raise ScopeError(f"{target.display!r} resolves to {value}; refused")
        if not allow_private and (address.is_private or address.is_loopback or address.is_reserved):
            raise ScopeError(
                f"{target.display!r} resolves to the private address {value}; "
                "use --allow-private only for an isolated lab you own"
            )
    return addresses


def guard_report_targets(findings: Iterable, scope: ScopePolicy) -> List[object]:
    """Keep only findings whose target URL/host/IP is inside scope."""
    kept = []
    for finding in findings:
        value = str(getattr(finding, "target", "") or "")
        if "://" in value:
            allowed = scope.allows_url(value)
        else:
            host = value
            if value.count(":") == 1:
                candidate, _, port = value.rpartition(":")
                if port.isdigit():
                    host = candidate
            allowed = scope.allows_host(host) or scope.allows_ip(host)
        if allowed:
            kept.append(finding)
    return kept
