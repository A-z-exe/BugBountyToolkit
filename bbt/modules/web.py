"""Web application assessment for a single URL (or IP/host web service)."""
from __future__ import annotations

import re
from typing import List, Optional

from ..checks import (
    check_cookies,
    check_cors,
    check_http_methods,
    check_security_headers,
    check_tls,
    establish_baseline,
    probe_paths,
)
from ..findings import Finding
from ..target import Target
from .base import BaseModule


class WebModule(BaseModule):
    name = "web"
    description = "Security headers, cookies, TLS, CORS, methods and content discovery"
    modes = ("web", "full")
    required_tools = ()  # nikto is optional

    def applies(self, target: Target) -> bool:
        return target.kind == "url" or target.kind in ("host", "ip")

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        findings: List[Finding] = []
        base_url, resp = self._pick_base(target)
        if base_url is None or resp is None:
            return [
                Finding(
                    title="Web service unreachable",
                    severity="info",
                    category="web",
                    target=target.display,
                    description="No HTTP(S) service responded on the target.",
                    confidence="low",
                )
            ]

        scheme = base_url.split("://", 1)[0]
        self.ui.info(f"Assessing web service at {base_url}")

        findings.extend(check_security_headers(self.ctx, base_url, resp, scheme=scheme))
        findings.extend(check_cookies(self.ctx, base_url, resp, scheme=scheme))

        # CORS
        cors_findings, cors_data = check_cors(self.ctx, base_url)
        findings.extend(cors_findings)
        self.ctx.write_json("cors_analysis.json", cors_data, key="cors")

        # HTTP methods
        method_findings, method_data = check_http_methods(self.ctx, base_url)
        findings.extend(method_findings)
        self.ctx.write_json("http_methods.json", method_data, key="http_methods")

        # TLS
        if scheme == "https":
            port = target.port or 443
            tls_findings, tls_data = check_tls(self.ctx, target.host, port)
            findings.extend(tls_findings)
            if tls_data:
                self.ctx.write_json("tls_certificate.json", tls_data, key="tls")

        # HTML content review
        findings.extend(self._analyze_html(base_url, resp, scheme))

        # Content discovery
        findings.extend(self._discover_content(base_url))

        # robots.txt / sitemap quick capture
        self._capture_robots(base_url)

        return findings

    # ------------------------------------------------------------------
    def _pick_base(self, target: Target):
        if target.kind == "url":
            url = target.base_url
            return url, self.http.get(url)

        authority = target.host
        if target.port:
            authority = f"{target.host}:{target.port}"
        schemes = [target.scheme] if target.port else ["http", "https"]
        for scheme in schemes:
            url = f"{scheme}://{authority}/"
            resp = self.http.get(url)
            if resp is not None:
                return url, resp
        return None, None

    # ------------------------------------------------------------------
    def _analyze_html(self, url: str, resp, scheme: str) -> List[Finding]:
        findings: List[Finding] = []
        text = resp.text or ""
        if scheme == "http" and re.search(
            r"<input[^>]+type=[\"']?password", text, re.I
        ):
            findings.append(
                Finding(
                    title="Login form served over plain HTTP",
                    severity="high",
                    category="web",
                    target=url,
                    description=(
                        "A password field is served over unencrypted HTTP; credentials "
                        "can be intercepted on the network."
                    ),
                    evidence="<input type=password> found on an http:// page",
                    remediation="Serve all authentication over HTTPS and redirect HTTP to HTTPS.",
                )
            )

        for comment in re.findall(r"<!--(.*?)-->", text, re.S)[:25]:
            if re.search(r"(password|secret|api[_-]?key|token|TODO|FIXME|debug)", comment, re.I):
                snippet = re.sub(r"\s+", " ", comment).strip()[:160]
                findings.append(
                    Finding(
                        title="Sensitive information in HTML comment",
                        severity="low",
                        category="web",
                        target=url,
                        description="An HTML comment may disclose internal details.",
                        evidence=f"<!-- {snippet} -->",
                        remediation="Remove developer comments from production pages.",
                        confidence="medium",
                    )
                )
                break

        emails = sorted(
            set(
                re.findall(
                    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text
                )
            )
        )
        if emails:
            findings.append(
                Finding(
                    title="Email address(es) disclosed",
                    severity="info",
                    category="web",
                    target=url,
                    description="The page exposes email addresses that can be harvested.",
                    evidence=", ".join(emails[:10]),
                    remediation="Avoid embedding raw email addresses in public pages.",
                    confidence="low",
                )
            )
        return findings

    # ------------------------------------------------------------------
    def _discover_content(self, base_url: str) -> List[Finding]:
        paths = list(self.config.web_paths)
        paths += [f"/{word.lstrip('/')}" for word in self.config.dir_words]

        # Custom wordlist
        if self.config.wordlist:
            try:
                with open(self.config.wordlist, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        word = line.strip()
                        if word and not word.startswith("#"):
                            paths.append(f"/{word.lstrip('/')}")
            except OSError as exc:
                self.ui.warn(f"Could not read wordlist {self.config.wordlist}: {exc}")

        # de-duplicate while preserving order, then cap
        seen = set()
        unique = []
        for path in paths:
            if path not in seen:
                seen.add(path)
                unique.append(path)
        unique = unique[: self.config.max_paths]

        self.ui.info(f"Probing {len(unique)} paths for interesting content ...")
        baseline = establish_baseline(self.ctx, base_url)
        hits, findings = probe_paths(self.ctx, base_url, unique, baseline)
        self.ctx.write_json(
            "content_discovery.json",
            {"baseline": baseline, "hits": hits},
            key="content_discovery",
        )
        self.ui.ok(f"Content discovery found {len(hits)} interesting path(s)")
        return findings

    # ------------------------------------------------------------------
    def _capture_robots(self, base_url: str) -> None:
        robots_url = base_url.split("://", 1)[0] + "://" + base_url.split("://", 1)[1].split("/", 1)[0] + "/robots.txt"
        resp = self.http.get(robots_url, allow_redirects=False)
        if resp is not None and resp.status_code == 200 and resp.text:
            self.ctx.write_text("robots.txt", resp.text, key="robots")
