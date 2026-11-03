"""Passive recon: JavaScript endpoint extraction and subdomain takeover checks.

Everything here is read-only. Subdomains come from public certificate
transparency logs (crt.sh) and DNS; the module never claims a dangling name.
"""
from __future__ import annotations

import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from .context import ScanContext

_SCRIPT_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)
_API_RE = re.compile(r"""["'`](/api/[^"'`\s<>]{2,150})["'`]""")
_URL_PATH_RE = re.compile(r"""["'`](/(?:v\d+|graphql|swagger|openapi)[^"'`\s<>]{2,120})["'`]""")

#: CNAME suffixes that are commonly claimable after a service is deleted.
TAKEOVER_SERVICES: Dict[str, Dict[str, object]] = {
    "github.io": {
        "service": "GitHub Pages",
        "markers": ("there isn't a github pages site here", "for root urls"),
    },
    "herokuapp.com": {"service": "Heroku", "markers": ("no such app",)},
    "herokudns.com": {"service": "Heroku", "markers": ("no such app",)},
    "s3.amazonaws.com": {
        "service": "Amazon S3",
        "markers": ("nosuchbucket", "the specified bucket does not exist"),
    },
    "cloudfront.net": {"service": "CloudFront", "markers": ("bad request", "cloudfront")},
    "azurewebsites.net": {
        "service": "Azure",
        "markers": ("error 404 - web app not found", "web app not found"),
    },
    "cloudapp.azure.com": {"service": "Azure", "markers": ("error 404 - web app not found",)},
    "blob.core.windows.net": {"service": "Azure Blob", "markers": ("blobnotfound",)},
    "netlify.app": {"service": "Netlify", "markers": ("not found - request id",)},
    "netlify.com": {"service": "Netlify", "markers": ("not found - request id",)},
    "vercel.app": {"service": "Vercel", "markers": ("the deployment could not be found",)},
    "now.sh": {"service": "Vercel", "markers": ("the deployment could not be found",)},
    "pages.dev": {"service": "Cloudflare Pages", "markers": ("project not found",)},
    "workers.dev": {"service": "Cloudflare Workers", "markers": ("there is nothing here yet",)},
    "surge.sh": {"service": "Surge", "markers": ("project not found",)},
    "bitbucket.io": {"service": "Bitbucket", "markers": ("repository not found",)},
    "ghost.io": {"service": "Ghost", "markers": ("domain not configured",)},
    "readme.io": {"service": "ReadMe", "markers": ("project doesnt exist", "project doesn't exist")},
    "statuspage.io": {"service": "Statuspage", "markers": ("page not found",)},
    "zendesk.com": {"service": "Zendesk", "markers": ("this help center no longer exists",)},
    "freshdesk.com": {"service": "Freshdesk", "markers": ("account not found",)},
    "pantheonsite.io": {"service": "Pantheon", "markers": ("404 unknown site",)},
    "wpengine.com": {"service": "WP Engine", "markers": ("site not found",)},
    "myshopify.com": {"service": "Shopify", "markers": ("sorry, this shop is currently unavailable",)},
    "webflow.io": {"service": "Webflow", "markers": ("this site is not published",)},
    "unbounce.com": {"service": "Unbounce", "markers": ("this page is no longer available",)},
    "tilda.ws": {"service": "Tilda", "markers": ("the page you are looking for doesn't exist",)},
    "fly.dev": {"service": "Fly.io", "markers": ("app not found",)},
    "onrender.com": {"service": "Render", "markers": ("not found",)},
    "railway.app": {"service": "Railway", "markers": ("application not found",)},
    "notion.site": {"service": "Notion", "markers": ("page not found",)},
    "bubbleapps.io": {"service": "Bubble", "markers": ("this app is not available",)},
    "tumblr.com": {"service": "Tumblr", "markers": ("there's nothing here",)},
    "wordpress.com": {"service": "WordPress.com", "markers": ("doesn’t exist", "doesn't exist")},
    "desk.com": {"service": "Desk", "markers": ("this help center no longer exists",)},
    "helpjuice.com": {"service": "Helpjuice", "markers": ("not found",)},
}


def detect_takeover_service(cname: str) -> Optional[str]:
    name = (cname or "").strip().lower().rstrip(".")
    for suffix, info in TAKEOVER_SERVICES.items():
        if name == suffix or name.endswith("." + suffix):
            return str(info["service"])
    return None


def takeover_marker(cname: str, body: str) -> Optional[str]:
    name = (cname or "").strip().lower().rstrip(".")
    lowered = (body or "").lower()
    for suffix, info in TAKEOVER_SERVICES.items():
        if name == suffix or name.endswith("." + suffix):
            for marker in info["markers"]:  # type: ignore[index]
                if str(marker).lower() in lowered:
                    return str(marker)
            return None
    return None


def _same_origin(url: str, origin: str) -> bool:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}" == origin


def extract_js_endpoints(
    ctx: ScanContext,
    base_url: str,
    html: Optional[str] = None,
    max_scripts: int = 8,
) -> List[Dict[str, str]]:
    """Fetch same-origin JS bundles and extract API-looking paths."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if html is None:
        page = ctx.http.get(base_url)
        html = page.text if page is not None else ""
    scripts: List[str] = []
    for src in _SCRIPT_RE.findall(html or ""):
        absolute = urljoin(base_url, src)
        if _same_origin(absolute, origin) and absolute not in scripts:
            scripts.append(absolute)
    scripts = scripts[:max_scripts]

    found: Dict[str, str] = {}
    for script in scripts:
        response = ctx.http.get(script)
        if response is None or response.status_code != 200:
            continue
        text = (response.text or "")[:2_000_000]
        for match in _API_RE.findall(text) + _URL_PATH_RE.findall(text):
            path = match.strip()
            if len(path) <= 160 and path not in found:
                found[path] = script
    return [{"path": key, "source": value} for key, value in sorted(found.items())]


def _resolve(name: str) -> Dict[str, List[str]]:
    cnames: List[str] = []
    ips: List[str] = []
    try:
        hostname, aliases, addresses = socket.gethostbyname_ex(name)
        ips = sorted(addresses)
        for alias in aliases:
            alias = alias.rstrip(".").lower()
            if alias and alias != name.lower() and alias not in cnames:
                cnames.append(alias)
    except OSError:
        pass

    # dnspython gives an exact CNAME answer when installed; it is optional.
    try:
        import dns.resolver  # type: ignore

        try:
            answers = dns.resolver.resolve(name, "CNAME")
            for answer in answers:
                target = answer.target.to_text().rstrip(".").lower()
                if target and target not in cnames:
                    cnames.append(target)
        except Exception:
            pass
    except ImportError:
        pass
    return {"cnames": cnames, "ips": ips}


def enumerate_subdomains(domain: str, max_names: int = 200) -> List[Dict[str, object]]:
    """Collect subdomains from crt.sh and resolve their CNAME/A records."""
    names = set()
    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": "%." + domain, "output": "json"},
            timeout=25,
            headers={"User-Agent": "BBT/%s" % "2.3"},
        )
        if response.status_code == 200:
            for row in response.json():
                for value in str(row.get("name_value") or "").splitlines():
                    value = value.strip().lower().lstrip("*.").rstrip(".")
                    if value == domain or value.endswith("." + domain):
                        names.add(value)
    except Exception:
        pass

    for common in ("www", "api", "app", "dev", "staging", "admin", "portal", "mail"):
        names.add(common + "." + domain)

    results: List[Dict[str, object]] = []
    for name in sorted(names)[: max(1, int(max_names))]:
        resolved = _resolve(name)
        results.append(
            {
                "name": name,
                "cnames": resolved["cnames"],
                "ips": resolved["ips"],
            }
        )
    return results
