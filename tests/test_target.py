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
        self.assertTrue(target.explicit_scheme)

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
        self.assertFalse(target.explicit_scheme)
        self.assertEqual(target.web_schemes, ["https", "http"])

    def test_ip_with_port(self):
        target = parse_target("192.168.1.10:8080")
        self.assertEqual(target.kind, "ip")
        self.assertEqual(target.host, "192.168.1.10")
        self.assertEqual(target.port, 8080)
        self.assertTrue(target.is_private)
        self.assertFalse(target.is_tls_likely)

    def test_host_port_and_path_without_scheme(self):
        target = parse_target("example.com:8080/admin?x=1")
        self.assertEqual(target.kind, "host")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.path, "/admin")
        self.assertEqual(target.query, "x=1")
        self.assertEqual(target.base_url, "https://example.com:8080/admin")

    def test_host_and_path_without_port(self):
        target = parse_target("example.com/portal/login")
        self.assertEqual(target.kind, "host")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.path, "/portal/login")

    def test_ipv6_url_uses_brackets_in_origin(self):
        target = parse_target("https://[::1]:8443/x")
        self.assertEqual(target.host, "::1")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.origin, "https://[::1]:8443")
        self.assertEqual(target.base_url, "https://[::1]:8443/x")

    def test_ipv6_host_with_port(self):
        target = parse_target("[::1]:8443")
        self.assertEqual(target.kind, "ip")
        self.assertEqual(target.host, "::1")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.authority, "[::1]:8443")

    def test_cidr_range(self):
        target = parse_target("10.0.0.0/24")
        self.assertEqual(target.kind, "cidr")
        self.assertTrue(target.is_private)
        self.assertTrue(target.is_range)

    def test_public_url_not_private(self):
        target = parse_target("https://example.com")
        self.assertFalse(target.is_private)

    def test_invalid_targets_raise(self):
        for value in ("", "   ", "http://", "ftp://example.com", "example.com:notaport"):
            with self.assertRaises(ValueError):
                parse_target(value)

    def test_control_characters_are_rejected(self):
        for value in (
            "https://example.com/\nrm -rf /",
            "https://example.com/\x00",
            "example.com\t",
        ):
            with self.assertRaises(ValueError):
                parse_target(value)


if __name__ == "__main__":
    unittest.main()
