"""Tests for utility helpers (no network access required)."""
import unittest

from bbt.utils import (
    expand_cidr,
    is_private_ip,
    parse_ports,
    safe_filename,
    same_site_host,
)


class UtilsTests(unittest.TestCase):
    def test_parse_ports_list_and_range(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("8000-8003"), [8000, 8001, 8002, 8003])
        self.assertEqual(parse_ports("443,80,80"), [80, 443])

    def test_parse_ports_default(self):
        self.assertEqual(parse_ports(None, default=[80, 443]), [80, 443])

    def test_parse_ports_invalid_specs_raise(self):
        for spec in ("abc", "80-abc", "70000", "0"):
            with self.assertRaises(ValueError):
                parse_ports(spec)

    def test_parse_ports_ignores_empty_chunks(self):
        self.assertEqual(parse_ports("80,,443"), [80, 443])

    def test_parse_ports_range_reversed(self):
        self.assertEqual(parse_ports("443-441"), [441, 442, 443])

    def test_expand_cidr_small(self):
        hosts = expand_cidr("192.168.1.0/30", max_hosts=10)
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_expand_cidr_limit(self):
        with self.assertRaises(ValueError):
            expand_cidr("10.0.0.0/16", max_hosts=10)

    def test_private_detection(self):
        self.assertTrue(is_private_ip("10.1.2.3"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))

    def test_safe_filename(self):
        self.assertEqual(safe_filename("https://example.com/a b"), "https_example.com_a_b")
        self.assertEqual(safe_filename(""), "target")

    def test_safe_filename_avoids_windows_reserved_names(self):
        for name in ("CON", "con.txt", "NUL", "COM1", "lpt9"):
            self.assertTrue(safe_filename(name).startswith("_"))
        self.assertEqual(safe_filename("console"), "console")

    def test_same_site_host(self):
        self.assertTrue(same_site_host("example.com", "example.com"))
        self.assertTrue(same_site_host("Example.COM", "example.com."))
        self.assertTrue(same_site_host("example.com", "www.example.com"))
        self.assertTrue(same_site_host("www.example.com", "example.com"))
        self.assertFalse(same_site_host("example.com", "evil.example.com"))
        self.assertFalse(same_site_host("example.com", "example.com.evil"))
        self.assertFalse(same_site_host("example.com", None))


if __name__ == "__main__":
    unittest.main()
