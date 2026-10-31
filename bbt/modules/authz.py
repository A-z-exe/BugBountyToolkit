"""BOLA / IDOR testing with two authenticated accounts.

Successful authentication does not mean successful authorization. This module
replays object-level endpoints (``/exports/{id}/manifest``, ``?user_id=42`` …)
with a second, lower-privileged account and compares the responses.

It only sends GET requests. Every result is a lead and must be verified
manually, because public objects legitimately look identical to both accounts.
"""
from __future__ import annotations

import difflib
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from ..checks import resolve_web_entry
from ..crawl import crawl_site
from ..findings import Finding
from ..http_client import HttpClient
from ..ids import collect_ids, extract_ids, ids_from_url
from ..openapi import endpoints as spec_endpoints
from ..openapi import fetch_spec
from ..target import Target
from .base import BaseModule

_LOGIN_HINTS = (
    'type="password"',
    "type='password'",
    'name="password"',
    "name='password'",
    'id="password"',
    "id='password'",
)

_ADMIN_PATHS = ("/admin/", "/administrator/", "/wp-admin/", "/server-status")
_ADMIN_HINTS = ("dashboard", "logout", "sign out", "settings", "users", "administrator")

_OBJECT_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip",
)


def _looks_like_login(text: str) -> bool:
    lowered = (text or "").lower()
    return any(hint in lowered for hint in _LOGIN_HINTS)


def _similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return difflib.SequenceMatcher(None, left[:3000], right[:3000]).ratio()


def _looks_like_object_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    if path.endswith(_OBJECT_EXTENSIONS):
        return False
    return bool(ids_from_url(url))


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url.rstrip("/")


def _replace_id(url: str, old: str, new: str) -> str:
    """Replace an object ID in the path/query without touching the host."""
    parsed = urlparse(url)
    path = "/".join(new if segment == old else segment for segment in parsed.path.split("/"))
    query = urlencode(
        [(name, new if value == old else value) for name, value in parse_qsl(parsed.query)]
    )
    return urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


class AuthzModule(BaseModule):
    name = "authz"
    description = "BOLA/IDOR checks with a second account"
    modes = ("web", "api", "full")
    required_tools = ()

    def applies(self, target: Target) -> bool:
        return target.is_web

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        if not (self.config.headers_b or self.config.cookies_b):
            self.ui.info(
                "Authz/BOLA checks skipped (add --header-b and/or --cookie-b "
                "for a second account)"
            )
            return []

        base_url, _resp = resolve_web_entry(self.ctx, target)
        if not base_url:
            self.ui.info("Authz/BOLA checks skipped (target is unreachable)")
            return []

        crawl = self.ctx.recall("crawl")
        if crawl is None and self.config.max_pages > 0:
            crawl = crawl_site(self.ctx, base_url)
        crawl = crawl or {}
        spec = fetch_spec(self.ctx, base_url) or {}
        page = self.http.get(base_url)
        page_ids = extract_ids(page.text or "") if page is not None else []

        candidates = self._candidate_urls(base_url, crawl, spec, page_ids)
        if not candidates:
            self.ui.info("Authz/BOLA checks: no object URLs or IDs to test")
            return []

        self.ui.info(f"Testing {len(candidates)} object URL(s) with the second account ...")
        http_b = HttpClient(
            self.config,
            rate_limiter=self.ctx.http.limiter,
            logger=self.log,
            headers=self.config.headers_b,
            cookies=self.config.cookies_b,
        )
        http_anon = HttpClient(
            self.config,
            rate_limiter=self.ctx.http.limiter,
            logger=self.log,
            headers={},
            cookies={},
        )
        findings: List[Finding] = []
        results: List[Dict[str, object]] = []
        try:
            for url in candidates:
                record, finding = self._compare(url, http_b, http_anon)
                if record is not None:
                    results.append(record)
                if finding is not None:
                    findings.append(finding)
            findings.extend(self._admin_surface(base_url, http_b))
        finally:
            http_b.close()
            http_anon.close()

        self.ctx.write_json("authz_results.json", results, key="authz")
        return findings

    # ------------------------------------------------------------------
    def _candidate_urls(
        self,
        base_url: str,
        crawl: Dict[str, object],
        spec: Dict[str, object],
        page_ids: Optional[List[str]] = None,
    ) -> List[str]:
        urls: List[str] = []
        seen = set()

        def add(url: str) -> None:
            if not url or url in seen:
                return
            seen.add(url)
            urls.append(url)

        # URLs that already contain an object reference.
        for url in list(crawl.get("urls") or []) + list(crawl.get("param_urls") or []):
            if _looks_like_object_url(str(url)):
                add(str(url))

        provided: List[str] = []
        for value in self.config.authz_ids:
            if value and value not in provided:
                provided.append(value)

        # Replay crawled object URLs with tester-supplied IDs (IDOR enumeration).
        if provided:
            for url in list(crawl.get("urls") or []) + list(crawl.get("param_urls") or []):
                existing = ids_from_url(str(url))
                if not existing:
                    continue
                for old in existing[:2]:
                    for new in provided[:5]:
                        if old != new:
                            add(_replace_id(str(url), old, new))

        # Build URLs from documented path/query parameters.
        harvested = collect_ids(
            [str(u) for u in (crawl.get("urls") or [])]
            + [str(u) for u in (crawl.get("param_urls") or [])]
        )
        for value in page_ids or []:
            if value not in harvested:
                harvested.append(value)
        values = provided + [value for value in harvested if value not in provided]
        if not values:
            values = ["1"]
        root = _origin(base_url)

        for endpoint in spec_endpoints(spec):
            if str(endpoint.get("method", "")).upper() != "GET":
                continue
            path = str(endpoint.get("path") or "")
            params = endpoint.get("params") or []
            used_value = values[0]
            resolved_path = path
            if "{" in path:
                for param in params:
                    if str(param.get("in")) != "path":
                        continue
                    name = str(param.get("name") or "")
                    if not name:
                        continue
                    lowered = name.lower()
                    value = (
                        "0"
                        if lowered in ("part", "part_no", "page", "offset", "limit", "index", "start")
                        else used_value
                    )
                    resolved_path = resolved_path.replace(
                        "{" + name + "}", quote(value, safe="")
                    )
                if "{" in resolved_path:
                    continue
            url = root + "/" + resolved_path.lstrip("/")
            query_params = [
                param
                for param in params
                if str(param.get("in")) == "query"
                and str(param.get("name") or "").lower().endswith("id")
            ]
            if query_params:
                query = urlencode(
                    {str(param["name"]): used_value for param in query_params}
                )
                url = f"{url}{'&' if '?' in url else '?'}{query}"
            add(url)

        if not urls and base_url:
            add(base_url)

        return [u for u in urls if _looks_like_object_url(u)][: self.config.max_authz_urls]

    # ------------------------------------------------------------------
    def _compare(self, url: str, http_b: HttpClient, http_anon: Optional[HttpClient] = None) -> Tuple[Optional[Dict[str, object]], Optional[Finding]]:
        response_a = self.http.get(url)
        if response_a is None or response_a.status_code >= 400:
            return None, None
        if _looks_like_login(response_a.text or ""):
            return None, None

        response_b = http_b.get(url)
        if response_b is None:
            return None, None

        record: Dict[str, object] = {
            "url": url,
            "a_status": response_a.status_code,
            "a_length": len(response_a.text or ""),
            "b_status": response_b.status_code,
            "b_length": len(response_b.text or ""),
        }
        if response_b.status_code >= 400:
            record["verdict"] = "protected"
            return record, None
        if response_b.status_code not in (200, 201, 202, 203, 204, 206):
            record["verdict"] = "inconclusive"
            return record, None
        if _looks_like_login(response_b.text or ""):
            record["verdict"] = "login-page"
            return record, None

        # If the same object is readable without any credentials, it is public
        # and cannot demonstrate BOLA.
        if http_anon is not None:
            response_anon = http_anon.get(url)
            record["anon_status"] = (
                response_anon.status_code if response_anon is not None else None
            )
            if (
                response_anon is not None
                and response_anon.status_code == 200
                and _similarity(response_a.text or "", response_anon.text or "") >= 0.90
            ):
                record["verdict"] = "public"
                return record, None

        similarity = _similarity(response_a.text or "", response_b.text or "")
        record["similarity"] = round(similarity, 3)
        record["verdict"] = "potential-bola" if similarity >= 0.90 else "different-content"
        if similarity < 0.90:
            return record, None

        severity = "high" if similarity >= 0.98 else "medium"
        confidence = "medium" if similarity >= 0.98 else "low"
        finding = Finding(
            title="Potential BOLA/IDOR: object accessible to both accounts",
            severity=severity,
            category="authz",
            target=url,
            description=(
                "The same object URL returned comparable content for both authenticated "
                "accounts. Successful authentication does not prove authorization; "
                "verify whether the second account is allowed to read this object."
            ),
            evidence=(
                f"A: HTTP {response_a.status_code}, {record['a_length']} bytes; "
                f"B: HTTP {response_b.status_code}, {record['b_length']} bytes; "
                f"similarity {similarity:.2f}"
            ),
            remediation=(
                "Enforce object ownership on the server for every request, not only at "
                "login. Prefer unguessable IDs and test with two accounts."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
            ],
            confidence=confidence,
        )
        return record, finding

    # ------------------------------------------------------------------
    def _admin_surface(self, base_url: str, http_b: HttpClient) -> List[Finding]:
        findings: List[Finding] = []
        root = _origin(base_url)
        for path in _ADMIN_PATHS:
            response = http_b.get(root + path, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            text = response.text or ""
            if _looks_like_login(text):
                continue
            lowered = text.lower()
            if not any(hint in lowered for hint in _ADMIN_HINTS):
                continue
            findings.append(
                Finding(
                    title=f"Second account can access administrative area: {path}",
                    severity="high",
                    category="authz",
                    target=root + path,
                    description=(
                        "A path that looks administrative returned a normal page to the "
                        "second account instead of a login/403 response."
                    ),
                    evidence=f"HTTP 200, {len(text)} bytes",
                    remediation=(
                        "Enforce role checks on every admin route and test with a "
                        "low-privileged account."
                    ),
                    confidence="medium",
                )
            )
        return findings
