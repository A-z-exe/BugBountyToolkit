"""Shared fakes for the offline unit tests."""
from __future__ import annotations

import logging
from typing import Callable, Dict, Optional

from bbt.config import Config


class FakeUI:
    def info(self, *args, **kwargs):
        pass

    def ok(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

    def found(self, *args, **kwargs):
        pass

    def header(self, *args, **kwargs):
        pass


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
        json_data=None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.cookies = []
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


class FakeHttp:
    """Dispatches requests to a handler ``(method, url, kwargs) -> response``."""

    def __init__(self, handler: Callable):
        self.handler = handler
        self.requests = []

    def _do(self, method: str, url: str, **kwargs):
        self.requests.append((method.upper(), url))
        return self.handler(method.upper(), url, kwargs)

    def get(self, url: str, **kwargs):
        return self._do("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._do("POST", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self._do("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self._do("HEAD", url, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        return self._do(method, url, **kwargs)


class FakeContext:
    def __init__(self, http: Optional[FakeHttp] = None, config: Optional[Config] = None):
        self.config = config or Config(rate=0)
        self.http = http or FakeHttp(lambda method, url, kwargs: None)
        self.state: Dict[str, object] = {}
        self.artifacts: Dict[str, str] = {}
        self.written: Dict[str, object] = {}
        self.logger = logging.getLogger("bbt.tests")
        self.ui = FakeUI()
        self.target = None
        self.output_dir = "."

    def remember(self, key, value):
        self.state[key] = value
        return value

    def recall(self, key, default=None):
        return self.state.get(key, default)

    def write_json(self, name, data, key=None):
        self.written[name] = data
        self.artifacts[key or name] = name
        return name

    def write_text(self, name, text, key=None):
        self.written[name] = text
        self.artifacts[key or name] = name
        return name

    def artifact(self, name):
        return name
