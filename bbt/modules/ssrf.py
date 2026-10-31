"""SSRF probes for URL-like parameters.

The module is opt-in (``--ssrf`` or ``--ssrf-url``). It injects a callback URL
you control and a few benign internal targets, then looks for reflected
internal content or connection errors. Blind SSRF still needs manual checking
of your callback (Burp Collaborator, webhook.site, …).
"""
from __future__ import annotations

import time
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..checks import resolve_web_entry
from ..crawl import crawl_site
from ..findings import Finding
from ..target import Target
from .base import BaseModule

SSRF_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "next", "return", "returnurl", "return_url",
    "host", "hostname", "domain", "webhook", "callback", "cb", "image", "img",
    "avatar", "file", "fileurl", "fetch", "proxy", "target", "feed", "rss",
    "path", "page", "load", "open", "resource", "endpoint", "api", "wsdl",
    "continue", "goto", "out", "u",
}

_INTERNAL_HINTS = (
    "root:x:0:0",
    "169.254.169.254",
    "latest/meta-data",
    "computemetadata",
    "iam/security-credentials",
    "redis_version",
    "mongodb",
    "elasticsearch",
)

_ERROR_HINTS = (
    "connection refused",
    "failed to connect",
    "econnrefused",
    "urlopen error",
    "no route to host",
    "name or service not known",
    "getaddrinfo failed",
    "could not resolve host",
    "connection timed out",
    "network is unreachable",
)


def _replace_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[name] = value
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(params), "")
    )


def _is_url_like(value: str) -> bool:
    value = (value or "").strip().lower()
    return value.startswith(("http://", "https://", "//"))


class SsrfModule(BaseModule):
    name = "ssrf"
    description = "SSRF probes on URL-like parameters"
    modes = ("web", "api", "full")
    required_tools = ()

    def applies(self, target: Target) -> bool:
        return target.is_web and self.config.ssrf_enabled

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        if not self.config.ssrf_enabled:
            return []
        base_url, _resp = resolve_web_entry(self.ctx, target)
        if not base_url:
            return []

        crawl = self.ctx.recall("crawl")
        if crawl is None and self.config.max_pages > 0:
            crawl = crawl_site(self.ctx, base_url)
        crawl = crawl or {}

        candidates: List[Tuple[str, str]] = []
        seen = set()
        urls = []
        if target.query:
            urls.append(target.url_with_query)
        urls.extend(str(url) for url in (crawl.get("param_urls") or []))
        for url in urls:
            parsed = urlparse(url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            for name, value in params.items():
                lowered = name.lower()
                if lowered not in SSRF_PARAM_NAMES and not _is_url_like(value):
                    continue
                key = (parsed.netloc, parsed.path, name)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((url, name))
                if len(candidates) >= self.config.max_ssrf_urls:
                    break
            if len(candidates) >= self.config.max_ssrf_urls:
                break

        if not candidates:
            self.ui.info("SSRF: no URL-like parameters found")
            return []

        token = "bbt" + str(int(time.time()))
        callback = self.config.ssrf_callback
        findings: List[Finding] = []
        results: List[Dict[str, object]] = []
        probes = 0
        self.ui.info(f"Testing {len(candidates)} parameter(s) for SSRF ...")

        for url, name in candidates:
            baseline = self.http.get(url)
            if baseline is None:
                continue
            base_text = (baseline.text or "").lower()
            base_status = baseline.status_code
            error_reported = False

            payloads: List[Tuple[str, str]] = [
                ("localhost", f"http://127.0.0.1:1/bbt-{token}"),
                ("localhost-v6", f"http://[::1]:1/bbt-{token}"),
            ]
            if callback:
                payloads.append(
                    ("callback", callback.rstrip("/") + f"/bbt-{token}")
                )
            if self.config.aggressive:
                payloads.append(
                    (
                        "cloud-metadata",
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    )
                )

            for label, payload in payloads:
                probe_url = _replace_param(url, name, payload)
                response = self.http.get(probe_url)
                probes += 1
                if response is None:
                    continue
                text = (response.text or "").lower()
                internal = [
                    hint for hint in _INTERNAL_HINTS if hint in text and hint not in base_text
                ]
                errors = [
                    hint for hint in _ERROR_HINTS if hint in text and hint not in base_text
                ]
                reflected_callback = bool(callback) and (
                    token.lower() in text or "bbt-" + token in text
                )
                record = {
                    "url": url,
                    "parameter": name,
                    "payload_type": label,
                    "baseline_status": base_status,
                    "status": response.status_code,
                    "internal_indicators": internal,
                    "error_indicators": errors,
                    "callback_reflected": reflected_callback,
                }
                results.append(record)

                if internal or reflected_callback:
                    findings.append(
                        Finding(
                            title=f"Potential SSRF via parameter '{name}' ({label})",
                            severity="high",
                            category="ssrf",
                            target=probe_url,
                            description=(
                                "The response changed after injecting a controlled URL and "
                                "contains internal-service or callback data. Confirm the "
                                "server actually made the request."
                            ),
                            evidence=(
                                f"payload: {payload}\n"
                                f"indicators: {', '.join(internal) or 'callback token reflected'}"
                            ),
                            remediation=(
                                "Allowlist outbound destinations, block link-local/loopback "
                                "ranges and metadata endpoints, and do not reflect raw fetch "
                                "errors back to users."
                            ),
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                            ],
                            confidence="medium",
                        )
                    )
                    break
                if errors and response.status_code >= 500 and base_status < 500 and not error_reported:
                    error_reported = True
                    findings.append(
                        Finding(
                            title=f"Possible SSRF (error-based) via parameter '{name}'",
                            severity="medium",
                            category="ssrf",
                            target=probe_url,
                            description=(
                                "A controlled URL caused a connection error/500 that the "
                                "baseline did not produce. This is a weak but useful signal."
                            ),
                            evidence=(
                                f"payload: {payload}\nstatus: {base_status} -> "
                                f"{response.status_code}\nindicator: {errors[0]}"
                            ),
                            remediation="Validate and allowlist outbound URLs; hide fetch errors.",
                            confidence="low",
                        )
                    )
                    # Keep going: a callback payload may still confirm blind SSRF.

        self.ctx.write_json("ssrf_results.json", results, key="ssrf")
        if callback and probes:
            findings.append(
                Finding(
                    title="SSRF callback probes sent (manual verification required)",
                    severity="info",
                    category="ssrf",
                    target=base_url,
                    description=(
                        f"{probes} probe(s) were sent with a unique token to your callback. "
                        "Check the Collaborator/webhook for incoming requests to confirm "
                        "out-of-band SSRF."
                    ),
                    evidence=f"callback: {callback}\ntoken: {token}\nprobes: {probes}",
                    confidence="high",
                )
            )
        return findings
