"""Tests for passive recon and subdomain takeover checks (no network)."""
import unittest
from unittest import mock

from bbt.config import Config
from bbt.modules.subdomain import SubdomainModule
from bbt.recon import (
    detect_takeover_service,
    extract_js_endpoints,
    takeover_marker,
)
from bbt.target import parse_target
from tests.fakes import FakeContext, FakeHttp, FakeResponse


class JsEndpointTests(unittest.TestCase):
    def test_extracts_api_paths_from_same_origin_bundles(self):
        def handler(method, url, kwargs):
            if url.endswith("/"):
                return FakeResponse(
                    200,
                    '<html><script src="/static/app.js"></script>'
                    '<script src="https://external.example/x.js"></script></html>',
                    {"Content-Type": "text/html"},
                )
            if url.endswith("/static/app.js"):
                return FakeResponse(
                    200,
                    'fetch("/api/users"); const a="/v1/orders";',
                    {"Content-Type": "application/javascript"},
                )
            return FakeResponse(404, "no")

        ctx = FakeContext(http=FakeHttp(handler), config=Config(rate=0))
        endpoints = extract_js_endpoints(ctx, "https://target.example/")
        paths = {item["path"] for item in endpoints}
        self.assertIn("/api/users", paths)
        self.assertIn("/v1/orders", paths)
        # External scripts must never be fetched.
        self.assertFalse(any("external.example" in item["source"] for item in endpoints))


class TakeoverFingerprintTests(unittest.TestCase):
    def test_service_detection(self):
        self.assertEqual(detect_takeover_service("foo.github.io"), "GitHub Pages")
        self.assertEqual(detect_takeover_service("bar.s3.amazonaws.com"), "Amazon S3")
        self.assertIsNone(detect_takeover_service("tech.virgool.io"))

    def test_unclaimed_page_marker(self):
        body = "<h1>There isn't a GitHub Pages site here.</h1>"
        self.assertIsNotNone(takeover_marker("foo.github.io", body))
        self.assertIsNone(takeover_marker("foo.github.io", "<h1>My live blog</h1>"))


class SubdomainModuleTests(unittest.TestCase):
    def test_takeover_fingerprint_is_reported(self):
        ctx = FakeContext(
            http=FakeHttp(
                lambda method, url, kwargs: FakeResponse(
                    200, "There isn't a GitHub Pages site here.", {"Content-Type": "text/html"}
                )
            ),
            config=Config(rate=0, subdomain_enum=True),
        )
        module = SubdomainModule(ctx)
        rows = [
            {
                "name": "dev.example.com",
                "cnames": ["dev.github.io"],
                "ips": [],
            }
        ]
        with mock.patch("bbt.modules.subdomain.enumerate_subdomains", return_value=rows):
            findings = module.run(parse_target("https://example.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("subdomain takeover", findings[0].title.lower())
        self.assertIn("subdomains.json", ctx.written)

    def test_live_subdomain_is_not_reported(self):
        ctx = FakeContext(
            http=FakeHttp(
                lambda method, url, kwargs: FakeResponse(
                    200, "<h1>My live blog</h1>", {"Content-Type": "text/html"}
                )
            ),
            config=Config(rate=0, subdomain_enum=True),
        )
        module = SubdomainModule(ctx)
        rows = [{"name": "tech.example.com", "cnames": ["route.virgool.io"], "ips": []}]
        with mock.patch("bbt.modules.subdomain.enumerate_subdomains", return_value=rows):
            findings = module.run(parse_target("https://example.com"))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
