"""HTTP client wrapper.

A thin layer over :mod:`requests` that adds rate limiting, sane defaults for
internal (often self-signed) sites and a tolerant error model: a failed request
returns ``None`` instead of raising, so modules can stay readable.
"""
from __future__ import annotations

import logging
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests

try:  # urllib3 ships with requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

from .config import Config
from .utils import RateLimiter, same_site_host

log = logging.getLogger("bbt.http")


class HttpClient:
    def __init__(
        self,
        config: Config,
        rate_limiter: Optional[RateLimiter] = None,
        logger: Optional[logging.Logger] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.config = config
        self.log = logger or log
        self.limiter = rate_limiter or RateLimiter(config.rate)
        effective_headers = config.headers if headers is None else headers
        effective_cookies = config.cookies if cookies is None else cookies
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": config.user_agent,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.8",
            }
        )
        if config.proxy:
            self.session.proxies.update({"http": config.proxy, "https": config.proxy})
        if effective_headers:
            self.session.headers.update(effective_headers)
        if effective_cookies:
            self.session.cookies.update(effective_cookies)
        adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    # ------------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        allow_redirects: Optional[bool] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        self.limiter.wait()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_tls)
        follow = self.config.follow_redirects if allow_redirects is None else allow_redirects
        try:
            response = self.session.request(
                method, url, allow_redirects=False, **kwargs
            )
            if not follow:
                return response
            return self._follow_redirects(response, method, **kwargs)
        except requests.exceptions.RequestException as exc:
            self.log.debug("request failed %s %s: %s", method, url, exc)
            return None

    def _follow_redirects(
        self, response: requests.Response, method: str, **kwargs
    ) -> requests.Response:
        """Follow redirects only while they stay on the scanned site.

        ``requests`` follows every hop by default, which lets a single
        redirect take a scan to a different host (a common way to escape the
        authorized scope or poison results). Each hop is rate limited and
        cross-site hops are returned to the caller unfollowed.
        """
        original_host = urlparse(response.url or "").hostname
        current = response
        next_method = method.upper()
        max_redirects = max(1, int(getattr(self.config, "max_redirects", 10)))
        for _ in range(max_redirects):
            if not getattr(current, "is_redirect", False):
                return current
            location = current.headers.get("Location")
            if not location:
                return current
            next_url = urljoin(current.url, location)
            target_host = urlparse(next_url).hostname
            if not same_site_host(original_host, target_host):
                self.log.info(
                    "not following cross-site redirect %s -> %s",
                    current.url,
                    next_url,
                )
                return current
            if current.status_code == 303 or (
                current.status_code in (301, 302) and next_method == "POST"
            ):
                next_method = "GET"
                for key in ("data", "json", "files"):
                    kwargs.pop(key, None)
            self.limiter.wait()
            current = self.session.request(
                next_method, next_url, allow_redirects=False, **kwargs
            )
        return current

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
