"""Non-destructive injection checks: reflected XSS, error-based SQLi, open redirect.

By default these checks only send benign probes. Time-based SQL injection is
only attempted when ``--aggressive`` is set, because it sends intrusive payloads.

Parameters are taken from the target URL and from URLs discovered by the
crawler, instead of blasting a fixed list of guessed parameter names at every
path. That keeps the noise (and the false-positive rate) down.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..checks import resolve_web_entry
from ..crawl import crawl_site
from ..findings import Finding
from ..target import Target
from .base import BaseModule

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "postgresql",
    "sqlite3",
    "sqlite error",
    "ora-0",
    "oracle error",
    "odbc sql server driver",
    "microsoft ole db provider",
    "syntax error at or near",
    "sqlstate",
]

REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirect_url", "next", "url",
                   "return", "returnurl", "return_url", "dest", "destination",
                   "continue", "target", "r", "u", "link", "out", "goto"}


class InjectionModule(BaseModule):
    name = "injection"
    description = "Reflected XSS, error-based SQLi and open redirect checks"
    modes = ("injection", "full")
    required_tools = ()

    def applies(self, target: Target) -> bool:
        return target.is_web

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        base_url, _resp = resolve_web_entry(self.ctx, target)
        if base_url is None:
            return []

        findings: List[Finding] = []
        crawl = self.ctx.recall("crawl")
        if crawl is None and self.config.max_pages > 0:
            crawl = crawl_site(self.ctx, base_url)
        crawl = crawl or {}
        if crawl and "crawl" not in self.ctx.artifacts:
            self.ctx.write_json("crawl.json", crawl, key="crawl")

        candidates: List[str] = []
        if target.query:
            candidates.append(target.url_with_query)
        else:
            candidates.append(base_url)
        for url in (crawl.get("param_urls") or [])[: self.config.max_injection_urls]:
            candidates.append(str(url))

        # De-duplicate on (host, path, parameter name) so a crawled site with
        # many links to the same endpoint is only tested once per parameter.
        tested = set()
        param_count = 0
        for url in candidates:
            parsed = urlparse(url)
            values = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if not values:
                continue
            for name in list(values)[: self.config.max_injection_params]:
                key = (parsed.netloc, parsed.path or "/", name)
                if key in tested:
                    continue
                tested.add(key)
                base_value = values.get(name) or "1"
                try:
                    findings.extend(self._test_param(parsed, values, name, base_value))
                except Exception as exc:  # noqa: BLE001 - never abort the scan
                    self.log.debug("injection test failed for %s: %s", name, exc)
                param_count += 1

        if param_count == 0:
            findings.append(
                Finding(
                    title="No testable parameters discovered",
                    severity="info",
                    category="injection",
                    target=base_url,
                    description=(
                        "The target URL and the crawled pages did not expose any query "
                        "parameters, so XSS/SQLi probes were not sent. Provide a URL "
                        "with parameters or increase --max-pages."
                    ),
                    confidence="high",
                )
            )
        else:
            self.ui.info(f"Tested {param_count} parameter(s) for injection issues")
        return findings

    # ------------------------------------------------------------------
    def _url_with(self, parsed, values: Dict[str, str], name: str, payload: str) -> str:
        merged = dict(values)
        merged[name] = payload
        query = urlencode(merged)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))

    def _test_param(self, parsed, values, name, base_value) -> List[Finding]:
        findings: List[Finding] = []
        base_url = self._url_with(parsed, values, name, base_value)
        started = time.monotonic()
        base_resp = self.http.get(base_url)
        base_time = time.monotonic() - started
        if base_resp is None:
            return findings
        base_text = base_resp.text or ""

        token = "bbt9v3x"
        payload = f"{token}'\"><img src=x onerror={token}>"
        probed = self._url_with(parsed, values, name, payload)
        resp = self.http.get(probed)
        if resp is not None:
            body = resp.text or ""
            if token in body and payload in body:
                findings.append(
                    Finding(
                        title=f"Possible reflected XSS in parameter '{name}'",
                        severity="medium",
                        category="xss",
                        target=probed,
                        description=(
                            f"The value of '{name}' is reflected verbatim in the response, "
                            "including HTML-breaking characters."
                        ),
                        evidence=f"Payload reflected: {payload[:80]}",
                        remediation=(
                            "Context-aware output encoding and a strict Content-Security-Policy; "
                            "validate manually to confirm execution."
                        ),
                        confidence="low",
                    )
                )

        # Error-based SQL injection.
        for injection in (f"{base_value}'", f'{base_value}"'):
            sqli_url = self._url_with(parsed, values, name, injection)
            sqli_resp = self.http.get(sqli_url)
            if sqli_resp is None:
                continue
            text = (sqli_resp.text or "").lower()
            base_lower = base_text.lower()
            for signature in SQL_ERROR_SIGNATURES:
                if signature in text and signature not in base_lower:
                    findings.append(
                        Finding(
                            title=f"Possible SQL injection in parameter '{name}'",
                            severity="high",
                            category="sqli",
                            target=sqli_url,
                            description=(
                                f"A database error signature appeared after injecting into '{name}'."
                            ),
                            evidence=f"Signature: {signature!r}",
                            remediation=(
                                "Use parameterised queries / prepared statements and validate "
                                "input. Confirm manually before reporting."
                            ),
                            confidence="medium",
                        )
                    )
                    break

        # Open redirect.
        if name.lower() in REDIRECT_PARAMS:
            payload_url = "https://evil.example/bbt"
            redirect_url = self._url_with(parsed, values, name, payload_url)
            redirect_resp = self.http.get(redirect_url, allow_redirects=False)
            if redirect_resp is not None:
                location = redirect_resp.headers.get("Location", "")
                if "evil.example" in location:
                    findings.append(
                        Finding(
                            title=f"Open redirect via parameter '{name}'",
                            severity="medium",
                            category="open-redirect",
                            target=redirect_url,
                            description="The application redirects to an attacker-controlled URL.",
                            evidence=f"Location: {location}",
                            remediation="Allowlist redirect destinations or use relative paths only.",
                            confidence="high",
                        )
                    )

        # Time-based SQLi (aggressive only).
        if self.config.aggressive:
            payloads = [
                f"{base_value}' OR SLEEP(5)-- -",
                f"{base_value}'; WAITFOR DELAY '0:0:5'--",
            ]
            for payload in payloads:
                tb_url = self._url_with(parsed, values, name, payload)
                started = time.monotonic()
                self.http.get(tb_url)
                elapsed = time.monotonic() - started
                if elapsed - base_time > 4.0:
                    findings.append(
                        Finding(
                            title=f"Possible time-based SQL injection in parameter '{name}'",
                            severity="high",
                            category="sqli",
                            target=tb_url,
                            description="A time-delay payload significantly increased response time.",
                            evidence=f"baseline {base_time:.2f}s vs payload {elapsed:.2f}s",
                            remediation="Use parameterised queries. Confirm manually.",
                            confidence="low",
                        )
                    )
                    break

        return findings
