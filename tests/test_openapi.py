"""Tests for OpenAPI parsing (no network)."""
import unittest

from bbt.openapi import endpoints, fetch_spec, path_parameters
from tests.fakes import FakeContext, FakeHttp, FakeResponse


SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/api/exports/{export_id}/manifest": {
            "get": {
                "parameters": [
                    {
                        "name": "export_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ]
            }
        },
        "/api/exports/{export_id}/parts/{part_no}": {
            "get": {"parameters": [{"$ref": "#/components/parameters/Part"}]}
        },
        "/api/users": {
            "get": {
                "parameters": [
                    {"name": "user_id", "in": "query", "required": False},
                    {"name": "q", "in": "query"},
                ]
            }
        },
    },
    "components": {
        "parameters": {
            "Part": {"name": "part_no", "in": "path", "required": True}
        }
    },
}


class OpenApiTests(unittest.TestCase):
    def test_endpoints_include_method_path_and_params(self):
        items = endpoints(SPEC)
        self.assertEqual(len(items), 3)
        manifest = next(item for item in items if item["path"].endswith("/manifest"))
        self.assertEqual(manifest["method"], "GET")
        self.assertEqual(manifest["params"][0]["name"], "export_id")
        self.assertEqual(manifest["params"][0]["in"], "path")

    def test_ref_parameters_are_resolved_and_path_params_added(self):
        items = endpoints(SPEC)
        parts = next(item for item in items if "parts" in item["path"])
        names = {param["name"] for param in parts["params"]}
        self.assertIn("export_id", names)
        self.assertIn("part_no", names)

    def test_path_parameters(self):
        self.assertEqual(
            path_parameters("/api/exports/{export_id}/parts/{part_no}"),
            ["export_id", "part_no"],
        )


class FetchSpecTests(unittest.TestCase):
    def test_fetch_spec_finds_and_caches(self):
        def handler(method, url, kwargs):
            if url.endswith("/openapi.json"):
                return FakeResponse(200, "{}", url=url, json_data=SPEC)
            return FakeResponse(404, "not found", url=url)

        http = FakeHttp(handler)
        ctx = FakeContext(http=http)
        spec = fetch_spec(ctx, "http://target/")
        self.assertIsNotNone(spec)
        self.assertIn("/api/users", spec["paths"])
        self.assertEqual(ctx.recall("openapi_spec"), spec)
        self.assertIn("api_spec.json", ctx.written)
        fetch_spec(ctx, "http://target/")
        self.assertEqual(len(http.requests), 1)


if __name__ == "__main__":
    unittest.main()
