"""Tests for target scope classification (no network access)."""
import logging
import unittest

from bbt.config import Config
from bbt.core import Scanner
from bbt.target import parse_target
from bbt.ui import UI


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner(Config(rate=0), UI(color=False), logging.getLogger("bbt.tests"))

    def test_public_ip_is_remote(self):
        self.assertEqual(self.scanner.classify(parse_target("8.8.8.8")), "remote")
        self.assertEqual(self.scanner.classify(parse_target("1.1.1.1")), "remote")

    def test_private_ip_is_local(self):
        self.assertEqual(self.scanner.classify(parse_target("10.1.2.3")), "local")
        self.assertEqual(self.scanner.classify(parse_target("127.0.0.1")), "local")

    def test_public_cidr_is_remote(self):
        self.assertEqual(self.scanner.classify(parse_target("45.33.32.0/24")), "remote")

    def test_private_cidr_is_local(self):
        self.assertEqual(self.scanner.classify(parse_target("192.168.0.0/24")), "local")

    def test_ipv6_public_and_private(self):
        self.assertEqual(
            self.scanner.classify(parse_target("2001:4860:4860::8888")), "remote"
        )
        self.assertEqual(self.scanner.classify(parse_target("fd00::1")), "local")

    def test_remote_scope_keeps_only_public_targets(self):
        self.scanner.config.scope = "remote"
        ordered = self.scanner.order_targets(
            [parse_target("10.0.0.5"), parse_target("8.8.8.8")]
        )
        self.assertEqual([target.host for target in ordered], ["8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
