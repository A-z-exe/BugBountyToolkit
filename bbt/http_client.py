"""HTTP client wrapper.

A thin layer over :mod:`requests` that adds rate limiting, sane defaults for
internal (often self-signed) sites and a tolerant error model: a failed request
returns ``None`` instead of raising, so modules can stay readable.
"""
from __future__ import annotations

import logging
from typing import Dict, Optional

import requests

try:  # urllib3 ships with requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

from .config import Config
from .utils import RateLimiter

log = logging.getLogger("bbt.http")


class HttpClient:
    def __init__(
        self,
        config: Config,
        rate_limiter: Optional[RateLimiter] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.log = logger or log
        self.limiter = rate_limiter or RateLimiter(config.rate)
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
        if allow_redirects is None:
            allow_redirects = self.config.follow_redirects
        try:
            return self.session.request(
                method, url, allow_redirects=allow_redirects, **kwargs
            )
        except requests.exceptions.RequestException as exc:
            self.log.debug("request failed %s %s: %s", method, url, exc)
            return None

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
