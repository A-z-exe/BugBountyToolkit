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

    def test_tls_verification_is_on_by_default(self):
        args = parse_arguments(["-t", "https://example.com", "-m", "web"])
        self.assertTrue(build_config(args, headers={}, cookies={}).verify_tls)

    def test_insecure_flag_disables_tls_verification(self):
        args = parse_arguments(
            ["-t", "https://example.com", "-m", "web", "--insecure"]
        )
        self.assertFalse(build_config(args, headers={}, cookies={}).verify_tls)

    def test_auto_mode_options_reach_config(self):
        args = parse_arguments(
            [
                "-t",
                "https://example.com",
                "-m",
                "auto",
                "--authorized",
                "--scope-file",
                "scope.txt",
                "--scope-host",
                "example.com",
                "--deep",
                "--screenshots",
                "--max-tool-findings",
                "50",
                "--allow-private",
            ]
        )
        config = build_config(args, headers={}, cookies={})
        self.assertTrue(config.authorized_pocs)
        self.assertTrue(config.hunt_deep)
        self.assertTrue(config.screenshots)
        self.assertTrue(config.allow_private)
        self.assertEqual(config.max_tool_findings, 50)
        self.assertEqual(args.scope_file, "scope.txt")
        self.assertEqual(args.scope_host, ["example.com"])

    def test_recon_and_report_options_reach_config(self):
        args = parse_arguments(
            [
                "-t",
                "https://example.com",
                "-m",
                "full",
                "--subdomain-enum",
                "--max-subdomains",
                "50",
                "--no-js-extract",
                "--no-bounty-reports",
                "--write-pocs",
                "--i-have-authorization",
            ]
        )
        config = build_config(args, headers={}, cookies={})
        self.assertTrue(config.subdomain_enum)
        self.assertEqual(config.max_subdomains, 50)
        self.assertFalse(config.extract_js)
        self.assertFalse(config.bounty_reports)
        self.assertTrue(config.write_pocs)
        self.assertTrue(config.authorized_pocs)


if __name__ == "__main__":
    unittest.main()
