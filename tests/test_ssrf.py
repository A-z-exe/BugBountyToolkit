"""Tests for SSRF probing (no network)."""
import unittest

from bbt.config import Config
from bbt.modules.ssrf import SsrfModule, _is_url_like, _replace_param
from bbt.target import parse_target
from tests.fakes import FakeContext, FakeHttp, FakeResponse


def _handler(method, url, kwargs):
    if "127.0.0.1" in url or "%5B%3A%3A1%5D" in url:
        return FakeResponse(500, "Connection refused", url=url)
    return FakeResponse(200, "<html>ok</html>", url=url)


class SsrfTests(unittest.TestCase):
    def test_error_based_ssrf_is_reported(self):
        config = Config(rate=0, ssrf_enabled=True, max_pages=0)
        ctx = FakeContext(http=FakeHttp(_handler), config=config)
        module = SsrfModule(ctx)
        findings = module.run(parse_target("http://target/?url=http://example.com"))
        self.assertTrue(any(finding.category == "ssrf" for finding in findings))
        self.assertTrue(
            any("error-based" in finding.title.lower() for finding in findings)
        )

    def test_internal_content_is_high_severity(self):
        def handler(method, url, kwargs):
            if "127.0.0.1" in url:
                return FakeResponse(200, "root:x:0:0:root:/root:/bin/bash", url=url)
            return FakeResponse(200, "<html>ok</html>", url=url)

        config = Config(rate=0, ssrf_enabled=True, max_pages=0)
        ctx = FakeContext(http=FakeHttp(handler), config=config)
        findings = SsrfModule(ctx).run(parse_target("http://target/?url=http://example.com"))
        ssrf = [finding for finding in findings if finding.category == "ssrf"]
        self.assertTrue(any(finding.severity == "high" for finding in ssrf))

    def test_callback_probes_are_recorded(self):
        config = Config(
            rate=0,
            ssrf_enabled=True,
            ssrf_callback="https://callback.example",
            max_pages=0,
        )
        ctx = FakeContext(http=FakeHttp(_handler), config=config)
        findings = SsrfModule(ctx).run(parse_target("http://target/?url=http://example.com"))
        self.assertTrue(
            any("callback probes sent" in finding.title.lower() for finding in findings)
        )
        results = ctx.written.get("ssrf_results.json") or []
        self.assertTrue(
            any(item.get("payload_type") == "callback" for item in results)
        )

    def test_helpers(self):
        self.assertTrue(_is_url_like("https://x"))
        self.assertFalse(_is_url_like("hello"))
        self.assertIn(
            "127.0.0.1",
            _replace_param("http://t/?url=http://x&id=1", "url", "http://127.0.0.1"),
        )


if __name__ == "__main__":
    unittest.main()
