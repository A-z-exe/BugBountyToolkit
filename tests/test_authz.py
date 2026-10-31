"""Tests for BOLA/IDOR candidate generation and comparison (no network)."""
import unittest

from bbt.config import Config
from bbt.modules.authz import AuthzModule, _looks_like_object_url, _similarity
from tests.fakes import FakeContext, FakeHttp, FakeResponse


def _context(config):
    return FakeContext(
        http=FakeHttp(lambda method, url, kwargs: FakeResponse(200, "same body")),
        config=config,
    )


class AuthzTests(unittest.TestCase):
    def test_candidates_use_provided_id_with_openapi_path(self):
        config = Config(rate=0, authz_ids=["exp_6c2d91"], max_authz_urls=10)
        module = AuthzModule(_context(config))
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/exports/{export_id}/manifest": {
                    "get": {
                        "parameters": [
                            {"name": "export_id", "in": "path", "required": True}
                        ]
                    }
                }
            },
        }
        urls = module._candidate_urls("http://target/", {}, spec, [])
        self.assertIn("http://target/api/exports/exp_6c2d91/manifest", urls)

    def test_candidates_mutate_crawled_ids(self):
        config = Config(rate=0, authz_ids=["exp_aaaaaa"])
        module = AuthzModule(_context(config))
        crawl = {"urls": ["http://target/api/exports/exp_bbbbbb/manifest"]}
        urls = module._candidate_urls("http://target/", crawl, {}, [])
        self.assertIn("http://target/api/exports/exp_aaaaaa/manifest", urls)

    def test_same_object_for_both_accounts_is_flagged(self):
        config = Config(rate=0, headers_b={"Authorization": "Bearer B"})
        ctx = FakeContext(
            http=FakeHttp(lambda method, url, kwargs: FakeResponse(200, '{"data":"x"}')),
            config=config,
        )
        module = AuthzModule(ctx)
        http_b = FakeHttp(lambda method, url, kwargs: FakeResponse(200, '{"data":"x"}'))
        record, finding = module._compare("http://target/api/users/42", http_b)
        self.assertEqual(record["verdict"], "potential-bola")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")

    def test_forbidden_second_account_is_not_flagged(self):
        config = Config(rate=0, headers_b={"Authorization": "Bearer B"})
        ctx = FakeContext(
            http=FakeHttp(lambda method, url, kwargs: FakeResponse(200, "secret")),
            config=config,
        )
        module = AuthzModule(ctx)
        http_b = FakeHttp(lambda method, url, kwargs: FakeResponse(403, "denied"))
        record, finding = module._compare("http://target/api/users/42", http_b)
        self.assertEqual(record["verdict"], "protected")
        self.assertIsNone(finding)

    def test_login_page_for_second_account_is_not_flagged(self):
        config = Config(rate=0, headers_b={"Authorization": "Bearer B"})
        ctx = FakeContext(
            http=FakeHttp(lambda method, url, kwargs: FakeResponse(200, "secret")),
            config=config,
        )
        module = AuthzModule(ctx)
        http_b = FakeHttp(
            lambda method, url, kwargs: FakeResponse(
                200, '<form><input type="password"></form>'
            )
        )
        record, finding = module._compare("http://target/api/users/42", http_b)
        self.assertEqual(record["verdict"], "login-page")
        self.assertIsNone(finding)

    def test_public_object_is_not_flagged_as_bola(self):
        config = Config(rate=0, headers_b={"Authorization": "Bearer B"})
        ctx = FakeContext(
            http=FakeHttp(lambda method, url, kwargs: FakeResponse(200, "public data")),
            config=config,
        )
        module = AuthzModule(ctx)
        http_b = FakeHttp(lambda method, url, kwargs: FakeResponse(200, "public data"))
        http_anon = FakeHttp(
            lambda method, url, kwargs: FakeResponse(200, "public data")
        )
        record, finding = module._compare(
            "http://target/api/products/42", http_b, http_anon
        )
        self.assertEqual(record["verdict"], "public")
        self.assertIsNone(finding)

    def test_admin_surface_with_dashboard_is_flagged(self):
        config = Config(rate=0, headers_b={"Authorization": "Bearer B"})
        ctx = FakeContext(config=config)
        module = AuthzModule(ctx)
        http_b = FakeHttp(lambda method, url, kwargs: FakeResponse(200, "<h1>dashboard</h1>"))
        findings = module._admin_surface("http://target/", http_b)
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "high")

    def test_object_url_filter(self):
        self.assertTrue(_looks_like_object_url("http://x/api/users/42"))
        self.assertTrue(_looks_like_object_url("http://x/api/users/exp_6c2d91"))
        self.assertFalse(_looks_like_object_url("http://x/assets/app.css"))
        self.assertFalse(_looks_like_object_url("http://x/about"))

    def test_similarity(self):
        self.assertEqual(_similarity("abc", "abc"), 1.0)
        self.assertLess(_similarity("abc", "xyz"), 0.5)


if __name__ == "__main__":
    unittest.main()
