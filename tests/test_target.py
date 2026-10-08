"""Tests for target parsing and classification."""
import unittest

from bbt.target import parse_target


class ParseTargetTests(unittest.TestCase):
    def test_full_url(self):
        target = parse_target("https://example.com:8443/login?x=1")
        self.assertEqual(target.kind, "url")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.base_url, "https://example.com:8443/login")

    def test_query_string_preserved(self):
        target = parse_target("https://example.com/app?id=1&next=/home")
        self.assertEqual(target.query, "id=1&next=/home")
        self.assertEqual(target.base_url, "https://example.com/app")
        self.assertEqual(target.url_with_query, "https://example.com/app?id=1&next=/home")

    def test_host_without_scheme(self):
        target = parse_target("example.com")
        self.assertEqual(target.kind, "host")
        self.assertEqual(target.host, "example.com")
        self.assertIsNone(target.port)

    def test_ip_with_port(self):
        target = parse_target("192.168.1.10:8080")
        self.assertEqual(target.kind, "ip")
        self.assertEqual(target.host, "192.168.1.10")
        self.assertEqual(target.port, 8080)
        self.assertTrue(target.is_private)

    def test_cidr_range(self):
        target = parse_target("10.0.0.0/24")
        self.assertEqual(target.kind, "cidr")
        self.assertTrue(target.is_private)
        self.assertTrue(target.is_range)

    def test_public_url_not_private(self):
        target = parse_target("https://example.com")
        self.assertFalse(target.is_private)

    def test_invalid_targets_raise(self):
        for value in ("", "   ", "http://", "ftp://example.com"):
            with self.assertRaises(ValueError):
                parse_target(value)


if __name__ == "__main__":
    unittest.main()
