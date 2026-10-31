"""Tests for CLI option parsing (no network access)."""
import unittest

from bbt.cli import build_config, parse_arguments, parse_cookies, parse_headers


class CliOptionTests(unittest.TestCase):
    def test_headers_are_parsed(self):
        self.assertEqual(
            parse_headers(["Authorization: Bearer abc", "X-Test: 1"]),
            {"Authorization": "Bearer abc", "X-Test": "1"},
        )

    def test_invalid_header_raises(self):
        with self.assertRaises(ValueError):
            parse_headers(["NoColonHere"])

    def test_cookies_are_parsed(self):
        self.assertEqual(
            parse_cookies(["session=abc; theme=dark", "lang=en"]),
            {"session": "abc", "theme": "dark", "lang": "en"},
        )

    def test_invalid_cookie_raises(self):
        with self.assertRaises(ValueError):
            parse_cookies(["not-a-cookie"])

    def test_no_crawl_disables_pages(self):
        args = parse_arguments(
            ["-t", "https://example.com", "-m", "web", "--no-crawl"]
        )
        config = build_config(args, headers={}, cookies={})
        self.assertEqual(config.max_pages, 0)

    def test_auth_options_reach_config(self):
        args = parse_arguments(
            [
                "-t",
                "https://example.com",
                "-m",
                "web",
                "-H",
                "Authorization: Bearer abc",
                "--cookie",
                "session=xyz",
            ]
        )
        config = build_config(
            args,
            headers=parse_headers(args.header),
            cookies=parse_cookies(args.cookie),
        )
        self.assertEqual(config.headers["Authorization"], "Bearer abc")
        self.assertEqual(config.cookies["session"], "xyz")

    def test_second_account_and_ssrf_options_reach_config(self):
        args = parse_arguments(
            [
                "-t",
                "https://example.com",
                "-m",
                "web",
                "--header-b",
                "Authorization: Bearer B",
                "--cookie-b",
                "session=b",
                "--authz-id",
                "exp_6c2d91",
                "--ssrf-url",
                "https://callback.example",
            ]
        )
        config = build_config(
            args,
            headers=parse_headers(args.header),
            cookies=parse_cookies(args.cookie),
            headers_b=parse_headers(args.header_b),
            cookies_b=parse_cookies(args.cookie_b),
        )
        self.assertEqual(config.headers_b["Authorization"], "Bearer B")
        self.assertEqual(config.cookies_b["session"], "b")
        self.assertEqual(config.authz_ids, ["exp_6c2d91"])
        self.assertTrue(config.ssrf_enabled)
        self.assertEqual(config.ssrf_callback, "https://callback.example")


if __name__ == "__main__":
    unittest.main()
