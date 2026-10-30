"""Tests for shared checks (no network access)."""
import unittest
from urllib.parse import urlparse

from bbt.checks import (
    body_signature,
    check_cookies,
    clean_web_base,
    origin_of,
    probe_paths,
    resolve_web_entry,
)
from bbt.target import parse_target


class FakeConfig:
    timeout = 5.0
    connect_timeout = 3.0


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, url=""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.cookies = []


class FakeHttp:
    def __init__(self, handler):
        self._handler = handler

    def get(self, url, **kwargs):
        return self._handler(url, kwargs)

    def options(self, url, **kwargs):
        return None

    def request(self, method, url, **kwargs):
        return None


class FakeContext:
    def __init__(self, http):
        self.config = FakeConfig()
        self.http = http
        self.state = {}

    def remember(self, key, value):
        self.state[key] = value
        return value

    def recall(self, key, default=None):
        return self.state.get(key, default)


SOFT_404 = "<html><body>Page not found.</body></html>"
SOFT_404_HEADERS = {"Content-Type": "text/html; charset=utf-8"}


def _baseline():
    length, digest = body_signature(SOFT_404)
    return {
        "status": 200,
        "length": length,
        "hash": digest,
        "content_type": "text/html; charset=utf-8",
        "ok": True,
    }


class ProbePathsTests(unittest.TestCase):
    def test_soft_404_is_not_a_hit(self):
        ctx = FakeContext(FakeHttp(lambda url, kw: FakeResponse(200, SOFT_404, SOFT_404_HEADERS)))
        hits, findings = probe_paths(ctx, "http://target", ["/admin/"], _baseline())
        self.assertEqual(hits, [])
        self.assertEqual(findings, [])

    def test_same_length_but_different_content_type_is_a_hit(self):
        # Regression test: a leaked .env whose body length happens to match the
        # soft-404 page must still be reported.
        def handler(url, kwargs):
            path = urlparse(url).path
            if path == "/.env":
                return FakeResponse(
                    200,
                    "DB_PASSWORD=supersecret\nAPI_KEY=deadbeef\n",
                    {"Content-Type": "text/plain"},
                )
            return FakeResponse(200, SOFT_404, SOFT_404_HEADERS)

        ctx = FakeContext(FakeHttp(handler))
        hits, findings = probe_paths(ctx, "http://target", ["/.env", "/admin/"], _baseline())
        self.assertEqual([hit["path"] for hit in hits], ["/.env"])
        self.assertTrue(
            any(finding.severity == "critical" and ".env" in finding.title for finding in findings)
        )

    def test_404_sensitive_path_is_skipped(self):
        ctx = FakeContext(FakeHttp(lambda url, kw: FakeResponse(404, "nope", SOFT_404_HEADERS)))
        hits, findings = probe_paths(ctx, "http://target", ["/.git/HEAD"], _baseline())
        self.assertEqual(hits, [])
        self.assertEqual(findings, [])


class CookieTests(unittest.TestCase):
    class Cookie:
        def __init__(self, name="session", secure=False, attributes=None):
            self.name = name
            self.secure = secure
            self._rest = attributes or {}

    def test_flags_are_case_insensitive(self):
        cookie = self.Cookie(
            secure=False,
            attributes={"HTTPOnly": None, "samesite": "Lax"},
        )
        resp = FakeResponse(200, "", {})
        resp.cookies = [cookie]
        ctx = FakeContext(FakeHttp(lambda url, kw: None))
        findings = check_cookies(ctx, "http://target/", resp, scheme="https")
        self.assertEqual(len(findings), 1)
        description = findings[0].description
        self.assertIn("Secure", description)
        self.assertNotIn("HttpOnly", description)
        self.assertNotIn("SameSite", description)

    def test_all_missing_flags_are_reported(self):
        resp = FakeResponse(200, "", {})
        resp.cookies = [self.Cookie()]
        ctx = FakeContext(FakeHttp(lambda url, kw: None))
        findings = check_cookies(ctx, "http://target/", resp, scheme="http")
        self.assertEqual(len(findings), 1)
        description = findings[0].description
        for flag in ("Secure", "HttpOnly", "SameSite"):
            self.assertIn(flag, description)


class UrlHelperTests(unittest.TestCase):
    def test_clean_web_base_drops_query_and_trailing_slash(self):
        self.assertEqual(
            clean_web_base("https://example.com/app/?x=1"),
            "https://example.com/app",
        )
        self.assertEqual(clean_web_base("https://example.com"), "https://example.com/")

    def test_origin_of(self):
        self.assertEqual(origin_of("https://example.com:8443/a/b"), "https://example.com:8443")


class WebEntryTests(unittest.TestCase):
    def test_bare_host_port_falls_back_to_http(self):
        # Regression test: HTTPS is tried first, but an HTTP-only internal app
        # must still be found instead of being reported as unreachable.
        def handler(url, kwargs):
            if url.startswith("https://"):
                return None
            return FakeResponse(200, "<html></html>", SOFT_404_HEADERS, url=url)

        ctx = FakeContext(FakeHttp(handler))
        base_url, resp = resolve_web_entry(ctx, parse_target("127.0.0.1:8080"))
        self.assertEqual(base_url, "http://127.0.0.1:8080/")
        self.assertIsNotNone(resp)

    def test_explicit_https_is_not_downgraded(self):
        seen = []

        def handler(url, kwargs):
            seen.append(url)
            return None

        ctx = FakeContext(FakeHttp(handler))
        base_url, resp = resolve_web_entry(ctx, parse_target("https://example.com"))
        self.assertIsNone(base_url)
        self.assertIsNone(resp)
        self.assertEqual(seen, ["https://example.com/"])


if __name__ == "__main__":
    unittest.main()
