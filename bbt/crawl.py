"""Bounded same-origin crawler.

The crawler is intentionally small and predictable: it never leaves the
target's origin, follows only a limited number of pages and feeds the
injection module with real URLs that carry query parameters.

Nothing here touches the network directly; every request goes through the
shared :class:`~bbt.http_client.HttpClient` so rate limiting and timeouts
still apply.
"""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from typing import Dict, List, Optional
from urllib.parse import urldefrag, urljoin, urlparse

from .context import ScanContext

#: Extensions that are never HTML pages; do not queue them.
_SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".avi", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z", ".iso", ".dmg",
    ".exe", ".msi", ".apk", ".jar", ".bin", ".sql",
)

_MAX_HTML_BYTES = 1_500_000

#: Links that perform a state change on GET; never crawl them automatically.
_UNSAFE_TOKENS = ("logout", "signout", "sign-out", "log-out", "destroy-session")


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else ""


def _is_html_like(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return not path.endswith(_SKIP_EXTENSIONS)


class _PageParser(HTMLParser):
    """Extract links, scripts and forms from a page without extra deps."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[Dict[str, object]] = []
        self.title = ""
        self._current_form: Optional[Dict[str, object]] = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_map = {str(k).lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area", "link", "iframe", "frame"):
            href = attrs_map.get("href")
            if href:
                self.links.append(href)
        elif tag in ("script", "img", "source"):
            src = attrs_map.get("src")
            if src:
                self.links.append(src)
                if tag == "script":
                    self.scripts.append(src)
        elif tag == "form":
            form: Dict[str, object] = {
                "action": attrs_map.get("action", ""),
                "method": (attrs_map.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(form)
            self._current_form = form
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            name = attrs_map.get("name")
            if name:
                inputs = self._current_form["inputs"]
                if isinstance(inputs, list) and name not in inputs:
                    inputs.append(name)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data

    def handle_startendtag(self, tag: str, attrs) -> None:
        # <input/> and friends are usually self-closing.
        self.handle_starttag(tag, attrs)


def crawl_site(
    ctx: ScanContext,
    start_url: str,
    max_pages: Optional[int] = None,
    max_depth: Optional[int] = None,
) -> Dict[str, object]:
    """Crawl ``start_url`` and return the discovered same-origin surface.

    The result is cached in the scan context, so web/api/injection modules can
    share one crawl per target.
    """
    cached = ctx.recall("crawl")
    if cached is not None:
        return cached

    if max_pages is None:
        max_pages = getattr(ctx.config, "max_pages", 25)
    if max_depth is None:
        max_depth = getattr(ctx.config, "crawl_depth", 2)
    max_pages = max(0, int(max_pages))
    max_depth = max(1, int(max_depth))

    origin = _origin(start_url)
    result: Dict[str, object] = {
        "start": start_url,
        "origin": origin,
        "pages": [],
        "urls": [],
        "param_urls": [],
        "forms": [],
        "scripts": [],
    }
    if max_pages == 0 or not origin:
        ctx.remember("crawl", result)
        return result

    queue = deque([(start_url, 0)])
    queued = {start_url}
    fetched = set()
    pages: List[Dict[str, object]] = []
    urls = set()
    forms: List[Dict[str, object]] = []
    scripts = set()

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in fetched:
            continue
        fetched.add(url)

        resp = ctx.http.get(url)
        if resp is None:
            continue
        status = getattr(resp, "status_code", 0) or 0
        if status >= 400:
            continue

        final_url = getattr(resp, "url", "") or url
        headers = getattr(resp, "headers", {}) or {}
        content_type = str(headers.get("Content-Type", "")).lower()
        if content_type and "html" not in content_type and "xml" not in content_type:
            continue

        text = getattr(resp, "text", "") or ""
        parser = _PageParser()
        try:
            parser.feed(text[:_MAX_HTML_BYTES])
            parser.close()
        except Exception:  # HTMLParser is forgiving, but never abort a crawl
            pass

        pages.append(
            {
                "url": final_url,
                "status": status,
                "title": parser.title.strip()[:120],
            }
        )

        for raw_link in parser.links:
            raw_link = raw_link.strip()
            if not raw_link:
                continue
            link = urldefrag(urljoin(final_url, raw_link))[0]
            parsed = urlparse(link)
            if parsed.scheme not in ("http", "https"):
                continue
            if _origin(link) != origin:
                continue
            if any(token in link.lower() for token in _UNSAFE_TOKENS):
                continue
            urls.add(link)
            if (
                depth < max_depth
                and link not in queued
                and _is_html_like(link)
            ):
                queued.add(link)
                queue.append((link, depth + 1))

        for discovered in parser.forms:
            action = urljoin(final_url, str(discovered.get("action") or final_url))
            if _origin(action) != origin:
                continue
            action = urldefrag(action)[0]
            if any(token in action.lower() for token in _UNSAFE_TOKENS):
                continue
            method = str(discovered.get("method") or "get").lower()
            inputs = [
                str(name)
                for name in (discovered.get("inputs") or [])
                if str(name).strip()
            ][:30]
            form = {
                "page": final_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            }
            forms.append(form)
            if method == "get" and inputs:
                query = "&".join(f"{name}=" for name in inputs)
                probe = f"{action}{'&' if '?' in action else '?'}{query}"
                urls.add(probe)

        for raw_script in parser.scripts:
            script_url = urldefrag(urljoin(final_url, raw_script.strip()))[0]
            if _origin(script_url) == origin:
                scripts.add(script_url)

    result["pages"] = pages
    result["urls"] = sorted(urls)
    result["param_urls"] = sorted({u for u in urls if urlparse(u).query})
    result["forms"] = forms[:200]
    result["scripts"] = sorted(scripts)[:200]
    ctx.remember("crawl", result)
    return result
