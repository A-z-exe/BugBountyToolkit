"""Reusable security checks shared by the web and API modules."""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from .context import ScanContext
from .findings import Finding
from .target import Target
from .utils import same_site_host

# ---------------------------------------------------------------------------
# Entry point resolution
# ---------------------------------------------------------------------------


def clean_web_base(url: str) -> str:
    """Normalize a URL into a base without query/fragment/trailing slash."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` for a URL (no trailing slash)."""
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url.rstrip("/")


def resolve_web_entry(
    ctx: ScanContext, target: Target
) -> Tuple[Optional[str], Optional[object]]:
    """Find a URL that actually answers HTTP(S) for this target.

    * An explicit ``https://``/``http://`` target is used as typed.
    * A bare ``host``/``ip`` (optionally with a port) is probed with HTTPS
      first and plain HTTP second, because internal apps are often HTTP-only.

    The result is cached per target so modules do not repeat the handshake.
    """
    cached = ctx.recall("web_entry")
    if cached:
        return cached.get("url"), cached.get("response")

    if target.kind == "url":
        candidates = [target.url_with_query]
    else:
        candidates = [
            f"{scheme}://{target.authority}/" for scheme in target.web_schemes
        ]

    for url in candidates:
        # Scheme probing should not hang for a full HTTP timeout on a dead port.
        timeout = ctx.config.timeout if target.explicit_scheme else min(
            ctx.config.timeout, 8.0
        )
        resp = ctx.http.get(url, timeout=timeout)
        if resp is None:
            continue
        final_url = resp.url or url
        if not same_site_host(target.host, urlparse(final_url).hostname):
            # A redirect to another host must not redefine the scanned origin.
            final_url = url
        base = clean_web_base(final_url)
        if not base.startswith(("http://", "https://")):
            base = clean_web_base(url)
        ctx.remember("web_entry", {"url": base, "response": resp})
        ctx.remember("web_scheme", urlparse(base).scheme)
        return base, resp
    return None, None


# ---------------------------------------------------------------------------
# Path probing
# ---------------------------------------------------------------------------

#: Paths whose presence is interesting regardless of status code mapping.
SENSITIVE_PATHS: Dict[str, Tuple[str, str]] = {
    "/.git/HEAD": ("high", "Exposed Git repository"),
    "/.git/config": ("high", "Exposed Git configuration"),
    "/.svn/entries": ("high", "Exposed Subversion metadata"),
    "/.env": ("critical", "Exposed environment file (.env)"),
    "/.DS_Store": ("low", "Exposed macOS metadata (.DS_Store)"),
    "/.htaccess": ("medium", "Exposed .htaccess file"),
    "/.htpasswd": ("high", "Exposed .htpasswd file"),
    "/phpinfo.php": ("medium", "Exposed phpinfo() page"),
    "/info.php": ("medium", "Exposed PHP information page"),
    "/server-status": ("medium", "Exposed Apache server-status"),
    "/server-info": ("medium", "Exposed Apache server-info"),
    "/web.config": ("high", "Exposed web.config"),
    "/WEB-INF/web.xml": ("high", "Exposed WEB-INF/web.xml"),
    "/actuator": ("medium", "Exposed Spring Boot Actuator"),
    "/actuator/health": ("low", "Exposed Spring Boot health endpoint"),
    "/actuator/env": ("high", "Exposed Spring Boot env endpoint"),
    "/backup.zip": ("high", "Exposed backup archive"),
    "/backup.tar.gz": ("high", "Exposed backup archive"),
    "/db.sql": ("critical", "Exposed database dump"),
    "/dump.sql": ("critical", "Exposed database dump"),
    "/wp-login.php": ("info", "WordPress login page exposed"),
    "/wp-admin/": ("info", "WordPress admin panel exposed"),
    "/wp-config.php.bak": ("critical", "Exposed WordPress config backup"),
    "/wp-config.php~": ("critical", "Exposed WordPress config backup"),
    "/wp-config.php.save": ("critical", "Exposed WordPress config backup"),
    "/wp-config.php.swp": ("critical", "Exposed WordPress config swap file"),
    "/wp-content/debug.log": ("high", "Exposed WordPress debug log"),
    "/debug.log": ("high", "Exposed debug log"),
    "/phpmyadmin/": ("medium", "phpMyAdmin exposed"),
    "/adminer.php": ("medium", "Adminer exposed"),
    "/swagger-ui.html": ("low", "API documentation (Swagger UI) exposed"),
    "/swagger/index.html": ("low", "API documentation (Swagger) exposed"),
    "/api-docs": ("low", "API documentation endpoint exposed"),
    "/openapi.json": ("low", "OpenAPI specification exposed"),
    "/graphql": ("low", "GraphQL endpoint exposed"),
    "/crossdomain.xml": ("low", "crossdomain.xml present"),
    "/clientaccesspolicy.xml": ("low", "Silverlight clientaccesspolicy.xml present"),
}

_CONTENT_STATUSES = {200, 201, 202, 204, 206}
_INTERESTING_STATUSES = _CONTENT_STATUSES | {301, 302, 303, 307, 308, 401, 500, 502, 503}


def body_signature(text: str) -> Tuple[int, str]:
    """Return (length, hash) of a normalized body for soft-404 detection."""
    sample = re.sub(r"\s+", " ", text or "").strip().lower()
    return len(sample), hashlib.sha1(sample.encode("utf-8", "ignore")).hexdigest()


def establish_baseline(ctx: ScanContext, base_url: str) -> Dict[str, object]:
    """Learn what a non-existent path looks like on this server."""
    probe = base_url.rstrip("/") + "/bbt-not-found-9f3a7c1e"
    resp = ctx.http.get(probe, allow_redirects=False)
    if resp is None:
        return {"status": None, "length": 0, "hash": "", "ok": False}
    length, digest = body_signature(resp.text)
    return {
        "status": resp.status_code,
        "length": length,
        "hash": digest,
        "content_type": resp.headers.get("Content-Type", ""),
        "ok": True,
    }


def _is_baseline_like(
    baseline: Dict[str, object],
    status: int,
    length: int,
    digest: str,
    content_type: str = "",
) -> bool:
    if not baseline.get("ok"):
        return False
    if status != baseline.get("status"):
        return False
    base_type = str(baseline.get("content_type") or "").split(";")[0].strip().lower()
    hit_type = str(content_type or "").split(";")[0].strip().lower()
    # A different media type is a strong signal that this is real content and
    # not the site's generic soft-404 page.
    if base_type and hit_type and base_type != hit_type:
        return False
    base_len = int(baseline.get("length") or 0)
    if digest and digest == baseline.get("hash"):
        return True
    if base_len == 0:
        return length == 0
    return abs(length - base_len) <= max(20, int(base_len * 0.10))


def probe_paths(
    ctx: ScanContext,
    base_url: str,
    paths: List[str],
    baseline: Optional[Dict[str, object]] = None,
) -> Tuple[List[Dict[str, object]], List[Finding]]:
    """Probe a list of paths, filter soft-404s and return hits + findings."""
    baseline = baseline if baseline is not None else establish_baseline(ctx, base_url)
    root = base_url.rstrip("/")
    hits: List[Dict[str, object]] = []
    findings: List[Finding] = []

    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        url = root + path
        resp = ctx.http.get(url, allow_redirects=False)
        if resp is None:
            continue
        status = resp.status_code
        length, digest = body_signature(resp.text)

        # A 404/410 is never an interesting hit, even for a sensitive path.
        if status in (404, 410):
            continue
        if status not in _INTERESTING_STATUSES and path not in SENSITIVE_PATHS:
            continue
        if _is_baseline_like(
            baseline,
            status,
            length,
            digest,
            resp.headers.get("Content-Type", ""),
        ):
            continue

        hit = {
            "path": path,
            "url": url,
            "status": status,
            "length": length,
            "content_type": resp.headers.get("Content-Type", ""),
            "redirect": resp.headers.get("Location", ""),
        }
        hits.append(hit)

        if path in SENSITIVE_PATHS:
            severity, title = SENSITIVE_PATHS[path]
            if status in _CONTENT_STATUSES:
                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        category="exposure",
                        target=url,
                        description=f"The resource {path} is accessible (HTTP {status}).",
                        evidence=f"HTTP {status}, {length} bytes, Content-Type: {hit['content_type']}",
                        remediation="Remove or restrict access to this resource in production.",
                    )
                )
            elif status in (401, 403):
                findings.append(
                    Finding(
                        title=f"{title} (access protected)",
                        severity="low",
                        category="exposure",
                        target=url,
                        description=(
                            f"{path} exists but returned HTTP {status}. "
                            "Verify the protection is intentional and robust."
                        ),
                        evidence=f"HTTP {status}",
                        confidence="low",
                    )
                )
        elif status in _CONTENT_STATUSES:
            findings.append(
                Finding(
                    title=f"Accessible path: {path}",
                    severity="info",
                    category="content-discovery",
                    target=url,
                    description=f"{path} returned HTTP {status} and may be worth reviewing.",
                    evidence=f"HTTP {status}, {length} bytes",
                    confidence="low",
                )
            )
        elif status in (301, 302, 303, 307, 308):
            findings.append(
                Finding(
                    title=f"Redirecting path: {path}",
                    severity="info",
                    category="content-discovery",
                    target=url,
                    description=f"{path} redirects to {hit['redirect']!r}.",
                    evidence=f"HTTP {status} -> {hit['redirect']}",
                    confidence="low",
                )
            )

    return hits, findings


# ---------------------------------------------------------------------------
# Transport (HTTP vs HTTPS)
# ---------------------------------------------------------------------------


def check_transport(ctx: ScanContext, url: str, scheme: str) -> List[Finding]:
    """Check whether the site is available over HTTPS and enforces it."""
    findings: List[Finding] = []
    parsed = urlparse(url)
    if not parsed.hostname:
        return findings
    timeout = min(ctx.config.timeout, 8.0)
    path = parsed.path or "/"

    if scheme == "http":
        https_url = urlunparse(("https", parsed.netloc, path, "", "", ""))
        https_resp = ctx.http.get(https_url, allow_redirects=False, timeout=timeout)
        if https_resp is None:
            findings.append(
                Finding(
                    title="Site is served over plain HTTP (no HTTPS)",
                    severity="high",
                    category="transport",
                    target=url,
                    description=(
                        "The HTTPS endpoint did not respond. Credentials, session cookies "
                        "and customer data can be intercepted or modified by anyone on the "
                        "network path."
                    ),
                    evidence=f"TLS connection to {https_url} failed",
                    remediation=(
                        "Install a TLS certificate (e.g. Let's Encrypt), serve the site only "
                        "over HTTPS, redirect HTTP to HTTPS with a 301 and enable HSTS."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
                    ],
                    confidence="high",
                )
            )
        else:
            if https_resp.status_code < 400:
                findings.append(
                    Finding(
                        title="HTTPS is available but not enforced",
                        severity="high",
                        category="transport",
                        target=url,
                        description=(
                            "The site is still served over HTTP even though an HTTPS listener "
                            "answers. Every request and the session cookie remain exposed."
                        ),
                        evidence=f"HTTPS endpoint responded with HTTP {https_resp.status_code}",
                        remediation=(
                            "Redirect all HTTP traffic to HTTPS (301), update absolute URLs and "
                            "set the Secure flag on session cookies."
                        ),
                        confidence="high",
                    )
                )
    elif scheme == "https":
        http_url = urlunparse(("http", parsed.netloc, path, "", "", ""))
        http_resp = ctx.http.get(http_url, allow_redirects=False, timeout=timeout)
        if http_resp is not None and http_resp.status_code < 400:
            location = http_resp.headers.get("Location", "")
            redirected = http_resp.status_code in (301, 302, 307, 308) and location.lower().startswith(
                "https://"
            )
            if not redirected:
                findings.append(
                    Finding(
                        title="HTTP is not redirected to HTTPS",
                        severity="medium",
                        category="transport",
                        target=http_url,
                        description=(
                            "The plain-HTTP version of the site answers without redirecting "
                            "to HTTPS, so users can be downgraded."
                        ),
                        evidence=f"HTTP {http_resp.status_code}"
                        + (f" -> {location}" if location else ""),
                        remediation="Return a 301 redirect from http:// to https://.",
                        confidence="high",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS for future visits",
    "Content-Security-Policy": "Mitigates XSS and content injection",
    "X-Frame-Options": "Mitigates clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer leakage",
    "Permissions-Policy": "Restricts powerful browser features",
}

_INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def check_security_headers(ctx: ScanContext, url: str, resp) -> List[Finding]:
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    missing = [h for h in SECURITY_HEADERS if h.lower() not in headers]
    if missing:
        severity = "medium" if "Content-Security-Policy" in missing else "low"
        findings.append(
            Finding(
                title=f"Missing security headers ({len(missing)})",
                severity=severity,
                category="headers",
                target=url,
                description="The response is missing recommended security headers: "
                + ", ".join(missing),
                evidence="\n".join(f"{h}: {SECURITY_HEADERS[h]}" for h in missing),
                remediation="Add the missing headers at the web server or application layer.",
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        )

    leaked = {h: headers[h.lower()] for h in _INFO_LEAK_HEADERS if h.lower() in headers}
    if leaked:
        findings.append(
            Finding(
                title="Server technology disclosure",
                severity="info",
                category="headers",
                target=url,
                description="Response headers reveal software/version information.",
                evidence="\n".join(f"{k}: {v}" for k, v in leaked.items()),
                remediation="Remove or minimise version-revealing headers.",
                confidence="high",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------


def _cookie_attributes(cookie) -> Dict[str, object]:
    """Return cookie extension attributes with lower-cased names.

    ``http.cookiejar`` keeps the case used on the wire, so ``HttpOnly``,
    ``HTTPOnly`` and ``httponly`` must all be treated as the same flag.
    """
    rest = getattr(cookie, "_rest", None) or {}
    return {str(key).lower(): value for key, value in rest.items()}


def check_cookies(ctx: ScanContext, url: str, resp, scheme: str = "https") -> List[Finding]:
    findings: List[Finding] = []
    cookies = getattr(resp, "cookies", None)
    if not cookies:
        return findings
    for cookie in cookies:
        issues = []
        attributes = _cookie_attributes(cookie)
        if not cookie.secure:
            issues.append("missing Secure flag")
        if "httponly" not in attributes:
            issues.append("missing HttpOnly flag")
        if "samesite" not in attributes:
            issues.append("missing SameSite attribute")
        if not issues:
            continue
        severity = "medium" if scheme == "http" else "low"
        if scheme == "http" and not cookie.secure:
            severity = "high"
        findings.append(
            Finding(
                title=f"Insecure cookie: {cookie.name}",
                severity=severity,
                category="cookies",
                target=url,
                description=f"Cookie '{cookie.name}' has: " + ", ".join(issues),
                evidence=f"Set-Cookie: {cookie.name}=... ({', '.join(issues)})",
                remediation="Set Secure, HttpOnly and SameSite attributes on sensitive cookies.",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def check_cors(ctx: ScanContext, url: str) -> Tuple[List[Finding], Dict[str, object]]:
    findings: List[Finding] = []
    results: Dict[str, object] = {}
    origins = ["https://evil.example", "https://attacker.example", "null"]

    for origin in origins:
        resp = ctx.http.get(url, headers={"Origin": origin})
        if resp is None:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower()
        record = {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac or None,
            "status": resp.status_code,
        }
        results[origin] = record

        reflected = bool(acao) and acao.strip() == origin
        wildcard = bool(acao) and acao.strip() == "*"
        credentials = acac == "true"

        if reflected and credentials:
            findings.append(
                Finding(
                    title="CORS: arbitrary origin reflected with credentials",
                    severity="high",
                    category="cors",
                    target=url,
                    description=(
                        "The server reflects an attacker-controlled Origin and allows "
                        "credentials, enabling cross-site data theft."
                    ),
                    evidence=f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}; "
                    f"Access-Control-Allow-Credentials: {acac}",
                    remediation="Allowlist trusted origins and never combine a reflected "
                    "origin with credentials.",
                    references=["https://portswigger.net/web-security/cors"],
                )
            )
        elif reflected and origin == "null":
            findings.append(
                Finding(
                    title="CORS: 'null' origin allowed",
                    severity="medium",
                    category="cors",
                    target=url,
                    description="The 'null' origin is accepted, which can be abused via sandboxed iframes.",
                    evidence=f"Origin: null -> Access-Control-Allow-Origin: {acao}",
                    remediation="Reject the 'null' origin and validate Origin against an allowlist.",
                )
            )
        elif reflected:
            findings.append(
                Finding(
                    title="CORS: arbitrary origin reflected",
                    severity="medium",
                    category="cors",
                    target=url,
                    description="The server reflects an arbitrary Origin in Access-Control-Allow-Origin.",
                    evidence=f"Origin: {origin} -> Access-Control-Allow-Origin: {acao}",
                    remediation="Validate Origin against an allowlist.",
                )
            )
        elif wildcard and credentials:
            findings.append(
                Finding(
                    title="CORS: wildcard origin with credentials",
                    severity="high",
                    category="cors",
                    target=url,
                    description="ACAO '*' combined with credentials is a dangerous misconfiguration.",
                    evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                    remediation="Use explicit origins when credentials are required.",
                )
            )
    return findings, results


# ---------------------------------------------------------------------------
# HTTP methods
# ---------------------------------------------------------------------------


def check_http_methods(ctx: ScanContext, url: str) -> Tuple[List[Finding], Dict[str, object]]:
    findings: List[Finding] = []
    results: Dict[str, object] = {}

    resp = ctx.http.options(url)
    allow = None
    if resp is not None:
        allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods")
    results["allow"] = allow

    if allow:
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        risky = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")]
        if risky:
            findings.append(
                Finding(
                    title="Potentially dangerous HTTP methods enabled",
                    severity="low",
                    category="http-methods",
                    target=url,
                    description="The server advertises methods that may allow unintended changes.",
                    evidence=f"Allow: {allow}",
                    remediation="Disable methods that are not required.",
                )
            )

    trace = ctx.http.request("TRACE", url)
    results["trace"] = trace.status_code if trace is not None else None
    if trace is not None and trace.status_code == 200:
        findings.append(
            Finding(
                title="HTTP TRACE method enabled",
                severity="low",
                category="http-methods",
                target=url,
                description="TRACE is enabled and may aid cross-site tracing attacks.",
                evidence="TRACE request returned HTTP 200",
                remediation="Disable the TRACE method.",
            )
        )
    return findings, results


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def check_tls(
    ctx: ScanContext,
    host: str,
    port: int,
    cert_info: Optional[Dict[str, object]] = None,
) -> Tuple[List[Finding], Dict[str, object]]:
    from .crypto import get_certificate_info

    findings: List[Finding] = []
    info = cert_info or get_certificate_info(
        host, port, timeout=ctx.config.connect_timeout + 2
    )
    if not info.get("ok"):
        # If TLS fails entirely on a URL the user said was https, that's notable.
        return findings, info

    if info.get("ok") and info.get("decoded") is False:
        findings.append(
            Finding(
                title="TLS certificate could not be fully decoded",
                severity="info",
                category="tls",
                target=f"{host}:{port}",
                description=(
                    "The TLS handshake worked but this Python runtime could not decode "
                    "the certificate, so expiry/subject checks were limited."
                ),
                evidence=f"error: {info.get('decode_error', 'unknown')}",
                confidence="high",
            )
        )

    subject = info.get("subject") or {}
    issuer = info.get("issuer") or {}
    self_signed = bool(info.get("self_signed"))
    if not self_signed and subject and subject == issuer:
        self_signed = True
    if self_signed:
        findings.append(
            Finding(
                title="Self-signed TLS certificate",
                severity="medium",
                category="tls",
                target=f"{host}:{port}",
                description="The certificate appears to be self-signed.",
                evidence=f"Subject: {subject}",
                remediation="Use a certificate issued by a trusted CA.",
            )
        )

    days = info.get("days_remaining")
    if isinstance(days, int):
        if days < 0:
            findings.append(
                Finding(
                    title="Expired TLS certificate",
                    severity="high",
                    category="tls",
                    target=f"{host}:{port}",
                    description="The TLS certificate has expired.",
                    evidence=f"notAfter: {info.get('not_after')} ({days} days)",
                    remediation="Renew the certificate.",
                )
            )
        elif days < 14:
            findings.append(
                Finding(
                    title="TLS certificate expiring soon",
                    severity="low",
                    category="tls",
                    target=f"{host}:{port}",
                    description=f"The certificate expires in {days} days.",
                    evidence=f"notAfter: {info.get('not_after')}",
                    remediation="Renew the certificate before expiry.",
                )
            )

    protocol = info.get("protocol")
    if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append(
            Finding(
                title=f"Outdated TLS protocol negotiated ({protocol})",
                severity="medium",
                category="tls",
                target=f"{host}:{port}",
                description="An outdated and insecure TLS/SSL protocol version was negotiated.",
                evidence=f"Protocol: {protocol}",
                remediation="Disable TLS 1.0/1.1 and SSLv2/3; require TLS 1.2+.",
            )
        )

    legacy = info.get("legacy_protocols") or []
    if legacy:
        findings.append(
            Finding(
                title="Legacy TLS protocol support enabled: " + ", ".join(legacy),
                severity="medium",
                category="tls",
                target=f"{host}:{port}",
                description=(
                    "The server still accepts deprecated TLS versions that are "
                    "vulnerable to downgrade and known protocol weaknesses."
                ),
                evidence="Accepted: " + ", ".join(legacy),
                remediation="Require TLS 1.2 or newer at the load balancer/server.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
            )
        )
    return findings, info
