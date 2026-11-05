"""Tests for redirect handling in the HTTP client (no network access)."""
import unittest
from unittest import mock

import requests
from requests.structures import CaseInsensitiveDict

from bbt.config import Config
from bbt.http_client import HttpClient


def _response(url, status_code=200, location=None):
    response = requests.Response()
    response.url = url
    response.status_code = status_code
    response.headers = CaseInsensitiveDict()
    if location:
        response.headers["Location"] = location
    return response


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.client = HttpClient(
            Config(rate=0, follow_redirects=True, max_redirects=5)
        )
        self.calls = []

    def _patch(self, handler):
        def side_effect(method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            return handler(method, url, kwargs)

        return mock.patch.object(
            self.client.session, "request", side_effect=side_effect
        )

    def test_same_site_redirect_is_followed(self):
        def handler(method, url, kwargs):
            if url == "http://target/":
                return _response(url, 302, "/login")
            return _response(url)

        with self._patch(handler):
            response = self.client.get("http://target/")
        self.assertEqual(response.url, "http://target/login")
        self.assertEqual(
            [call[1] for call in self.calls],
            ["http://target/", "http://target/login"],
        )
        self.assertTrue(all(call[2]["allow_redirects"] is False for call in self.calls))

    def test_www_variant_counts_as_same_site(self):
        def handler(method, url, kwargs):
            if url == "http://target/":
                return _response(url, 301, "http://www.target/home")
            return _response(url)

        with self._patch(handler):
            response = self.client.get("http://target/")
        self.assertEqual(response.url, "http://www.target/home")

    def test_cross_site_redirect_is_not_followed(self):
        def handler(method, url, kwargs):
            return _response(url, 302, "https://evil.example/collect")

        with self._patch(handler):
            response = self.client.get("http://target/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.calls), 1)

    def test_post_redirect_switches_to_get_and_drops_body(self):
        def handler(method, url, kwargs):
            if url == "http://target/login":
                return _response(url, 303, "/home")
            return _response(url)

        with self._patch(handler):
            self.client.post("http://target/login", data={"user": "x"})
        methods = [call[0] for call in self.calls]
        self.assertEqual(methods, ["POST", "GET"])
        self.assertNotIn("data", self.calls[1][2])

    def test_redirect_limit_is_enforced(self):
        def handler(method, url, kwargs):
            return _response(url, 302, "/loop")

        with self._patch(handler):
            response = self.client.get("http://target/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.calls), 6)  # initial request + 5 redirect hops

    def test_redirects_can_be_disabled(self):
        def handler(method, url, kwargs):
            return _response(url, 302, "https://evil.example/")

        with self._patch(handler):
            response = self.client.get("http://target/", allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
