"""WordPress detection, version review and common misconfiguration checks.

The channel's WordPress content (plugin upload bugs, Comment2Shell, XML-RPC and
user enumeration) maps to the checks below. Version comparisons use the public
WordPress.org API and are skipped when it is unreachable.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin

import requests

from ..checks import origin_of, resolve_web_entry
from ..findings import Finding
from ..target import Target
from .base import BaseModule

_PLUGIN_RE = re.compile(r"/wp-content/plugins/([A-Za-z0-9._-]+)/")
_THEME_RE = re.compile(r"/wp-content/themes/([A-Za-z0-9._-]+)/")
_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']WordPress\s+([0-9][0-9.]*)',
    re.I,
)
_GENERATOR_RE_REVERSED = re.compile(
    r'<meta[^>]+content=["\']WordPress\s+([0-9][0-9.]*)["\'][^>]*name=["\']generator["\']',
    re.I,
)
_FEED_GENERATOR_RE = re.compile(r"wordpress\.org/\?v=([0-9][0-9.]*)", re.I)
_VERSION_LINE_RE = re.compile(r"^(?:Version|Stable tag)\s*:\s*([0-9][0-9A-Za-z.\-]*)", re.I | re.M)

_WP_API_TIMEOUT = 6


def _version_tuple(value: str) -> Tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", value or "")][:4]
    return tuple(parts)


def _is_older(installed: str, latest: str) -> bool:
    left = _version_tuple(installed)
    right = _version_tuple(latest)
    return bool(left and right and left < right)


class WordpressModule(BaseModule):
    name = "wordpress"
    description = "WordPress detection, version and configuration review"
    modes = ("web", "full")
    required_tools = ()

    def applies(self, target: Target) -> bool:
        return target.is_web

    # ------------------------------------------------------------------
    def run(self, target: Target) -> List[Finding]:
        base_url, response = resolve_web_entry(self.ctx, target)
        if not base_url or response is None:
            return []
        root = origin_of(base_url)
        html = response.text or ""

        login = self.http.get(urljoin(root + "/", "wp-login.php"))
        wp_json = self.http.get(urljoin(root + "/", "wp-json/"))
        detected = bool(
            "wp-content" in html
            or "wp-json" in html
            or (
                login is not None
                and login.status_code == 200
                and ("wp-submit" in (login.text or "") or "WordPress" in (login.text or ""))
            )
            or (
                wp_json is not None
                and wp_json.status_code == 200
                and "namespaces" in (wp_json.text or "")
            )
        )
        if not detected:
            return []

        findings: List[Finding] = []
        findings.append(
            Finding(
                title="WordPress detected",
                severity="info",
                category="wordpress",
                target=root,
                description="The target runs WordPress; the review below targets its common attack surface.",
                confidence="high",
            )
        )

        version = self._core_version(html, root)
        latest_core = self._latest_core_version() if version else None
        if version and latest_core and _is_older(version, latest_core):
            findings.append(
                Finding(
                    title=f"Outdated WordPress core ({version} < {latest_core})",
                    severity="medium",
                    category="wordpress",
                    target=root,
                    description=(
                        "The detected core version is older than the current WordPress release. "
                        "Known core vulnerabilities may apply."
                    ),
                    evidence=f"installed: {version}\nlatest: {latest_core}",
                    remediation="Update WordPress core and keep automatic minor updates enabled.",
                    references=["https://wpscan.com/"],
                    confidence="medium",
                )
            )
        elif version:
            findings.append(
                Finding(
                    title=f"WordPress core version {version}",
                    severity="info",
                    category="wordpress",
                    target=root,
                    description=(
                        "Core version detected. Compare it with the latest release and the "
                        "plugin/theme versions below."
                    ),
                    evidence=f"installed: {version}"
                    + (f"\nlatest: {latest_core}" if latest_core else ""),
                    confidence="medium",
                )
            )

        findings.extend(self._xmlrpc(root))
        users = self._user_enumeration(root)
        findings.extend(users[0])
        plugins, themes = self._components(html)
        findings.extend(self._component_findings(root, "plugin", plugins))
        findings.extend(self._component_findings(root, "theme", themes))
        findings.extend(self._uploads_listing(root))

        self.ctx.write_json(
            "wordpress.json",
            {
                "root": root,
                "version": version,
                "latest_core": latest_core,
                "plugins": plugins,
                "themes": themes,
                "xmlrpc": self.ctx.recall("wp_xmlrpc", False),
                "users": users[1],
            },
            key="wordpress",
        )
        return findings

    # ------------------------------------------------------------------
    def _core_version(self, html: str, root: str) -> Optional[str]:
        for pattern in (_GENERATOR_RE, _GENERATOR_RE_REVERSED):
            match = pattern.search(html or "")
            if match:
                return match.group(1).rstrip(".")
        feed = self.http.get(urljoin(root + "/", "feed/"))
        if feed is not None and feed.status_code == 200:
            match = _FEED_GENERATOR_RE.search(feed.text or "")
            if match:
                return match.group(1).rstrip(".")
        readme = self.http.get(urljoin(root + "/", "readme.html"))
        if readme is not None and readme.status_code == 200:
            match = re.search(r"Version\s+([0-9][0-9.]*)", readme.text or "", re.I)
            if match:
                return match.group(1).rstrip(".")
        return None

    def _latest_core_version(self) -> Optional[str]:
        cached = self.ctx.recall("wp_latest_core")
        if cached is not None:
            return cached or None
        version = None
        try:
            response = requests.get(
                "https://api.wordpress.org/core/version-check/1.7/",
                timeout=_WP_API_TIMEOUT,
                proxies=self._proxies(),
            )
            data = response.json()
            offers = data.get("offers") or []
            if offers:
                version = str(offers[0].get("current") or "").strip() or None
        except Exception:  # noqa: BLE001 - optional external lookup
            version = None
        self.ctx.remember("wp_latest_core", version or "")
        return version

    def _xmlrpc(self, root: str) -> List[Finding]:
        payload = (
            '<?xml version="1.0"?><methodCall><methodName>system.listMethods'
            "</methodName><params></params></methodCall>"
        )
        response = self.http.post(
            urljoin(root + "/", "xmlrpc.php"),
            data=payload,
            headers={"Content-Type": "text/xml"},
        )
        enabled = bool(
            response is not None
            and response.status_code == 200
            and "methodResponse" in (response.text or "")
        )
        self.ctx.remember("wp_xmlrpc", enabled)
        if not enabled:
            return []
        return [
            Finding(
                title="WordPress XML-RPC is enabled",
                severity="medium",
                category="wordpress",
                target=urljoin(root + "/", "xmlrpc.php"),
                description=(
                    "XML-RPC allows authentication attempts and pingback calls; it is often "
                    "used for password brute force and SSRF/amplification."
                ),
                evidence="system.listMethods returned a valid methodResponse",
                remediation=(
                    "Disable XML-RPC if it is not required (server/WAF rule) and enforce "
                    "login rate limiting/2FA."
                ),
                confidence="high",
            )
        ]

    def _user_enumeration(self, root: str) -> Tuple[List[Finding], List[str]]:
        findings: List[Finding] = []
        users: List[str] = []
        response = self.http.get(urljoin(root + "/", "wp-json/wp/v2/users?per_page=10"))
        if response is not None and response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                data = None
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        value = item.get("slug") or item.get("name")
                        if value:
                            users.append(str(value))
                if users:
                    findings.append(
                        Finding(
                            title="WordPress users enumerable via REST API",
                            severity="medium",
                            category="wordpress",
                            target=urljoin(root + "/", "wp-json/wp/v2/users"),
                            description=(
                                "The REST API lists usernames, which makes password spraying "
                                "and targeted attacks easier."
                            ),
                            evidence=", ".join(users[:10]),
                            remediation=(
                                "Restrict /wp-json/wp/v2/users to authenticated users or "
                                "disable the users endpoint."
                            ),
                            confidence="high",
                        )
                    )
        author = self.http.get(root + "/?author=1", allow_redirects=False)
        if author is not None and author.status_code in (301, 302, 307, 308):
            location = author.headers.get("Location", "")
            if "/author/" in location:
                findings.append(
                    Finding(
                        title="WordPress author enumeration via redirect",
                        severity="low",
                        category="wordpress",
                        target=root + "/?author=1",
                        description="Author IDs redirect to usernames, leaking valid accounts.",
                        evidence=f"Location: {location}",
                        remediation="Disable author archives for unauthenticated users.",
                        confidence="medium",
                    )
                )
        return findings, users

    def _components(self, html: str) -> Tuple[List[str], List[str]]:
        plugins = sorted(set(_PLUGIN_RE.findall(html or "")))
        themes = sorted(set(_THEME_RE.findall(html or "")))
        return plugins[:20], themes[:10]

    def _component_findings(
        self, root: str, kind: str, slugs: List[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        base_path = "plugins" if kind == "plugin" else "themes"
        for slug in slugs:
            installed = self._installed_version(root, base_path, slug, kind)
            latest = None
            if installed:
                latest = (
                    self._latest_plugin_version(slug)
                    if kind == "plugin"
                    else self._latest_theme_version(slug)
                )
            if installed and latest and _is_older(installed, latest):
                findings.append(
                    Finding(
                        title=f"Outdated WordPress {kind}: {slug} ({installed} < {latest})",
                        severity="medium",
                        category="wordpress",
                        target=f"{root}/wp-content/{base_path}/{slug}/",
                        description=(
                            f"The installed {kind} version is older than the latest release. "
                            "Outdated plugins/themes are the most common WordPress RCE/XSS path."
                        ),
                        evidence=f"installed: {installed}\nlatest: {latest}",
                        remediation=f"Update {slug} to the latest version or remove it if unused.",
                        references=["https://wpscan.com/"],
                        confidence="medium",
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"WordPress {kind} detected: {slug}",
                        severity="info",
                        category="wordpress",
                        target=f"{root}/wp-content/{base_path}/{slug}/",
                        description=(
                            f"{kind.title()} detected"
                            + (f" (version {installed})" if installed else "")
                            + ". Check its changelog against known vulnerabilities."
                        ),
                        evidence=f"slug: {slug}" + (f"\ninstalled: {installed}" if installed else ""),
                        confidence="medium",
                    )
                )
        return findings

    def _installed_version(self, root: str, base_path: str, slug: str, kind: str) -> Optional[str]:
        if kind == "plugin":
            url = urljoin(root + "/", f"wp-content/{base_path}/{slug}/readme.txt")
        else:
            url = urljoin(root + "/", f"wp-content/{base_path}/{slug}/style.css")
        response = self.http.get(url)
        if response is None or response.status_code != 200:
            return None
        match = _VERSION_LINE_RE.search(response.text or "")
        return match.group(1).strip() if match else None

    def _latest_plugin_version(self, slug: str) -> Optional[str]:
        return self._wp_api_version(
            "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information"
            f"&request[slug]={quote(slug)}",
            "wp_plugin_versions",
            slug,
        )

    def _latest_theme_version(self, slug: str) -> Optional[str]:
        return self._wp_api_version(
            "https://api.wordpress.org/themes/info/1.2/?action=theme_information"
            f"&request[slug]={quote(slug)}",
            "wp_theme_versions",
            slug,
        )

    def _wp_api_version(self, url: str, cache_key: str, slug: str) -> Optional[str]:
        cache: Dict[str, str] = self.ctx.recall(cache_key) or {}
        if slug in cache:
            return cache[slug] or None
        version = None
        try:
            response = requests.get(
                url,
                timeout=_WP_API_TIMEOUT,
                proxies=self._proxies(),
            )
            data = response.json()
            version = str(data.get("version") or "").strip() or None
        except Exception:  # noqa: BLE001 - optional external lookup
            version = None
        cache[slug] = version or ""
        self.ctx.remember(cache_key, cache)
        return version

    def _uploads_listing(self, root: str) -> List[Finding]:
        url = urljoin(root + "/", "wp-content/uploads/")
        response = self.http.get(url)
        if response is None or response.status_code != 200:
            return []
        if "index of" not in (response.text or "").lower():
            return []
        return [
            Finding(
                title="Directory listing enabled: /wp-content/uploads/",
                severity="medium",
                category="wordpress",
                target=url,
                description="Uploaded files are browsable, which exposes private media and filenames.",
                evidence="HTTP 200 with an 'Index of' page",
                remediation="Disable directory listing and serve uploads through the application.",
                confidence="high",
            )
        ]

    def _proxies(self) -> Optional[Dict[str, str]]:
        if self.config.proxy:
            return {"http": self.config.proxy, "https": self.config.proxy}
        return None
