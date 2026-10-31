"""Identifier extraction helpers for BOLA/IDOR testing.

Bug bounty programs increasingly hide object references in prefixed IDs
(``exp_6c2d91``), UUIDs or plain integers. These helpers collect such values
from URLs, HTML and JSON so the authz module can replay object endpoints with
two different accounts.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Set
from urllib.parse import parse_qs, urlparse

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
PREFIXED_RE = re.compile(r"\b([A-Za-z]{2,10}_[A-Za-z0-9]{4,40})\b")
NUMERIC_RE = re.compile(r"^\d{1,12}$")

#: Parameter names commonly used for object references.
ID_PARAM_NAMES = {
    "id", "uid", "user", "userid", "user_id", "account", "account_id",
    "order", "order_id", "invoice", "invoice_id", "export", "export_id",
    "file", "file_id", "doc", "document", "document_id", "profile",
    "profile_id", "tenant", "tenant_id", "org", "org_id", "project",
    "project_id", "item", "item_id", "post", "post_id", "comment",
    "comment_id", "message", "message_id", "ticket", "ticket_id",
    "customer", "customer_id", "object", "object_id", "record", "record_id",
}

#: JSON keys whose values are worth collecting.
_ID_KEY_RE = re.compile(
    r'"(?P<key>[A-Za-z0-9_\-]*(?:id|Id|ID|uuid|key|ref))"\s*:\s*'
    r'(?:"(?P<str>[^"]{2,80})"|(?P<num>\d{1,12}))'
)


def looks_like_id(value: str) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    return bool(
        UUID_RE.fullmatch(value)
        or PREFIXED_RE.fullmatch(value)
        or NUMERIC_RE.fullmatch(value)
    )


def _add(values: List[str], seen: Set[str], value: str) -> None:
    value = (value or "").strip().strip('"\'')
    if value and len(value) <= 120 and looks_like_id(value) and value not in seen:
        seen.add(value)
        values.append(value)


def extract_ids(text: str, limit: int = 200) -> List[str]:
    """Collect ID-like values from HTML/JSON text."""
    text = text or ""
    values: List[str] = []
    seen: Set[str] = set()

    for match in UUID_RE.finditer(text):
        _add(values, seen, match.group(0))
        if len(values) >= limit:
            return values

    for match in PREFIXED_RE.finditer(text):
        _add(values, seen, match.group(1))
        if len(values) >= limit:
            return values

    for match in _ID_KEY_RE.finditer(text):
        _add(values, seen, match.group("str") or match.group("num") or "")
        if len(values) >= limit:
            return values

    return values


def ids_from_url(url: str) -> List[str]:
    """Collect IDs from path segments and ID-like query parameters."""
    parsed = urlparse(url)
    values: List[str] = []
    seen: Set[str] = set()

    for segment in (parsed.path or "").split("/"):
        _add(values, seen, segment)
        if len(values) >= 50:
            return values

    for name, items in parse_qs(parsed.query, keep_blank_values=True).items():
        lowered = name.lower()
        if lowered not in ID_PARAM_NAMES and not lowered.endswith("_id"):
            continue
        for item in items:
            _add(values, seen, item)
            if len(values) >= 50:
                return values

    return values


def collect_ids(sources: Iterable[str], limit: int = 200) -> List[str]:
    values: List[str] = []
    seen: Set[str] = set()
    for source in sources:
        for value in ids_from_url(source) + extract_ids(source):
            _add(values, seen, value)
            if len(values) >= limit:
                return values
    return values
