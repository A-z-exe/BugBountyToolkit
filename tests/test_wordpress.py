"""Tests for WordPress detection and review (no network)."""
import unittest
from urllib.parse import urlparse

from bbt.config import Config
from bbt.modules.wordpress import WordpressModule, _is_older
from bbt.target import parse_target
from tests.fakes import FakeContext, FakeHttp, FakeResponse

HOME = """
<html><head>
<meta name="generator" content="WordPress 6.0.1">
</head><body>
<link rel="stylesheet" href="/wp-content/themes/bar/style.css">
<script src="/wp-content/plugins/foo/app.js"></script>
</body></html>
"""


def _handler(method, url, kwargs):
    path = urlparse(url).path
    if path == "/":
        return FakeResponse(200, HOME, url=url)
    if path == "/wp-login.php":
        return FakeResponse(200, "<form id='loginform'><input name='log'><input type='submit' id='wp-submit'></form>", url=url)
    if path == "/wp-json/":
        return FakeResponse(200, '{"namespaces":["wp/v2"]}', url=url, json_data={"namespaces": ["wp/v2"]})
    if path == "/wp-json/wp/v2/users":
        return FakeResponse(
            200,
            "[]",
            url=url,
            json_data=[{"slug": "admin"}, {"slug": "editor"}],
        )
    if path == "/xmlrpc.php" and method == "POST":
        return FakeResponse(200, "<methodResponse><params/></methodResponse>", url=url)
    if path == "/wp-content/plugins/foo/readme.txt":
        return FakeResponse(200, "=== Foo ===\nStable tag: 1.0\n", url=url)
    if path == "/wp-content/themes/bar/style.css":
        return FakeResponse(200, "/*\nTheme Name: Bar\nVersion: 1.0\n*/\n", url=url)
    if path == "/wp-content/uploads/":
        return FakeResponse(200, "<h1>Index of /wp-content/uploads</h1>", url=url)
    return FakeResponse(404, "not found", url=url)


class WordPressTests(unittest.TestCase):
    def test_version_comparison_pads_missing_segments(self):
        self.assertFalse(_is_older("1.2", "1.2.0"))
        self.assertFalse(_is_older("6.5.0", "6.5"))
        self.assertTrue(_is_older("1.2", "1.2.1"))
        self.assertTrue(_is_older("6.4.3", "6.5"))

    def setUp(self):
        self.ctx = FakeContext(http=FakeHttp(_handler), config=Config(rate=0))
        self.module = WordpressModule(self.ctx)
        self.module._latest_core_version = lambda: "6.5"
        self.module._latest_plugin_version = lambda slug: "2.0"
        self.module._latest_theme_version = lambda slug: "2.0"

    def test_detects_and_reports_wordpress_issues(self):
        findings = self.module.run(parse_target("http://wp/"))
        titles = " || ".join(finding.title.lower() for finding in findings)
        self.assertIn("wordpress detected", titles)
        self.assertIn("outdated wordpress core", titles)
        self.assertIn("outdated wordpress plugin: foo", titles)
        self.assertIn("outdated wordpress theme: bar", titles)
        self.assertIn("xml-rpc is enabled", titles)
        self.assertIn("users enumerable", titles)
        self.assertIn("directory listing enabled", titles)
        self.assertIn("wordpress.json", self.ctx.written)

    def test_non_wordpress_site_is_ignored(self):
        ctx = FakeContext(
            http=FakeHttp(
                lambda method, url, kwargs: FakeResponse(
                    200, "<html><body>plain site</body></html>", url=url
                )
            ),
            config=Config(rate=0),
        )
        self.assertEqual(WordpressModule(ctx).run(parse_target("http://plain/")), [])


if __name__ == "__main__":
    unittest.main()
