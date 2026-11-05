"""Tests for the bounded same-origin crawler (no network access)."""
import unittest

from bbt.crawl import crawl_site


class FakeConfig:
    max_pages = 10
    crawl_depth = 2


class FakeResponse:
    def __init__(self, url, status_code=200, text="", content_type="text/html"):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.headers = {"Content-Type": content_type}


class FakeHttp:
    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def get(self, url, **kwargs):
        self.requested.append(url)
        if url not in self.pages:
            return FakeResponse(url, 404, "not found")
        return FakeResponse(url, 200, self.pages[url])


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


INDEX = """
<html><head><title>Home</title></head><body>
<a href="/a?x=1">A</a>
<a href="/about">About</a>
<a href="/logout?next=/">Logout</a>
<a href="https://external.example/out">External</a>
<a href="javascript:void(0)">JS</a>
<form method="get" action="/find"><input name="q"><input name="page"></form>
<script src="/app.js"></script>
</body></html>
"""


class CrawlTests(unittest.TestCase):
    def setUp(self):
        self.http = FakeHttp(
            {
                "http://site/": INDEX,
                "http://site/a?x=1": "<html><body>A page</body></html>",
                "http://site/about": "<html><body>About</body></html>",
                "http://site/find?q=&page=": "<html><body>Find</body></html>",
            }
        )
        self.ctx = FakeContext(self.http)

    def test_extracts_links_forms_and_params(self):
        result = crawl_site(self.ctx, "http://site/")
        self.assertEqual(result["origin"], "http://site")
        self.assertIn("http://site/a?x=1", result["urls"])
        self.assertIn("http://site/find?q=&page=", result["urls"])
        self.assertNotIn("https://external.example/out", result["urls"])
        self.assertNotIn("http://site/logout?next=/", result["urls"])
        self.assertIn("http://site/a?x=1", result["param_urls"])
        self.assertTrue(any(form["action"] == "http://site/find" for form in result["forms"]))
        self.assertIn("http://site/app.js", result["scripts"])
        self.assertEqual(result["pages"][0]["title"], "Home")

    def test_crawl_is_cached_per_target(self):
        first = crawl_site(self.ctx, "http://site/")
        second = crawl_site(self.ctx, "http://site/")
        self.assertIs(first, second)
        self.assertEqual(len(self.http.requested), len(set(self.http.requested)))

    def test_zero_pages_disables_crawl(self):
        result = crawl_site(self.ctx, "http://site/", max_pages=0)
        self.assertEqual(result["pages"], [])
        self.assertEqual(self.http.requested, [])

    def test_links_per_page_are_capped(self):
        html = "<html><body>" + "".join(
            f'<a href="/page{i}">p</a>' for i in range(5001)
        ) + "</body></html>"
        http = FakeHttp({"http://site/": html})
        ctx = FakeContext(http)
        result = crawl_site(ctx, "http://site/", max_pages=1)
        self.assertEqual(len(result["urls"]), 5000)


if __name__ == "__main__":
    unittest.main()
