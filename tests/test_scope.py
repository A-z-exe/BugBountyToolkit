"""Tests for authorization scope enforcement (no network access)."""
import tempfile
import unittest
from pathlib import Path

from bbt.findings import Finding
from bbt.scope import (
    ScopeError,
    ScopePolicy,
    guard_addresses,
    guard_report_targets,
    parse_scope_entry,
)
from bbt.target import parse_target


class ScopeEntryTests(unittest.TestCase):
    def test_domain_entry_includes_subdomains(self):
        entry = parse_scope_entry("example.com")
        self.assertTrue(entry.matches_host("example.com"))
        self.assertTrue(entry.matches_host("deep.app.example.com"))
        self.assertFalse(entry.matches_host("example.com.evil.test"))

    def test_wildcard_excludes_apex(self):
        entry = parse_scope_entry("*.example.com")
        self.assertFalse(entry.matches_host("example.com"))
        self.assertTrue(entry.matches_host("app.example.com"))

    def test_url_entry_is_host_and_port_aware(self):
        entry = parse_scope_entry("https://app.example.com:8443/")
        self.assertTrue(entry.matches_url("https://app.example.com:8443/login"))
        self.assertFalse(entry.matches_url("https://app.example.com/login"))
        self.assertFalse(entry.matches_url("https://other.example.com:8443/"))
        self.assertFalse(entry.matches_url("https://app.example.com.evil.test/"))

    def test_ip_and_cidr_entries(self):
        ip_entry = parse_scope_entry("203.0.113.10")
        cidr_entry = parse_scope_entry("203.0.113.0/24")
        self.assertTrue(ip_entry.matches_url("https://203.0.113.10/"))
        self.assertTrue(cidr_entry.matches_ip("203.0.113.99"))
        self.assertFalse(cidr_entry.matches_ip("203.0.114.1"))

    def test_unrestricted_entries_are_rejected(self):
        for value in ("*", "0.0.0.0/0", "::/0"):
            with self.assertRaises(ScopeError):
                parse_scope_entry(value)

    def test_invalid_entry_is_rejected(self):
        with self.assertRaises(ScopeError):
            parse_scope_entry("not a host")


class ScopePolicyTests(unittest.TestCase):
    def test_target_outside_scope_is_rejected(self):
        policy = ScopePolicy.from_entries(["example.com"])
        policy.assert_target(parse_target("https://app.example.com/login"))
        with self.assertRaises(ScopeError):
            policy.assert_target(parse_target("https://evil.test/"))

    def test_url_target_must_match_scope_host(self):
        policy = ScopePolicy.from_entries(["https://app.example.com"])
        policy.assert_target(parse_target("https://app.example.com/x"))
        with self.assertRaises(ScopeError):
            policy.assert_target(parse_target("https://example.com/x"))

    def test_cidr_target_must_be_inside_authorized_network(self):
        policy = ScopePolicy.from_entries(["203.0.113.0/24"])
        policy.assert_target(parse_target("203.0.113.0/28"))
        with self.assertRaises(ScopeError):
            policy.assert_target(parse_target("198.51.100.0/28"))

    def test_subdomain_support_depends_on_entry_kind(self):
        domain_scope = ScopePolicy.from_entries(["example.com"])
        url_scope = ScopePolicy.from_entries(["https://example.com"])
        self.assertTrue(domain_scope.supports_subdomains("example.com"))
        self.assertFalse(url_scope.supports_subdomains("example.com"))

    def test_scope_file_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.txt"
            path.write_text(
                "# program scope\n\nexample.com\n*.demo.test\n203.0.113.0/24\n",
                encoding="utf-8",
            )
            policy = ScopePolicy.from_file(path)
            self.assertEqual(len(policy), 3)
            self.assertTrue(policy.allows_host("www.example.com"))

    def test_scope_file_reports_line_number_on_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.txt"
            path.write_text("example.com\nnot a host\n", encoding="utf-8")
            with self.assertRaises(ScopeError) as caught:
                ScopePolicy.from_file(path)
            self.assertIn(":2:", str(caught.exception))


class AddressGuardTests(unittest.TestCase):
    def test_private_target_is_rejected_by_default(self):
        with self.assertRaises(ScopeError):
            guard_addresses(parse_target("http://127.0.0.1:8080"))

    def test_private_target_allowed_for_lab(self):
        self.assertEqual(
            guard_addresses(parse_target("http://127.0.0.1:8080"), allow_private=True),
            ["127.0.0.1"],
        )

    def test_metadata_address_is_always_rejected(self):
        with self.assertRaises(ScopeError):
            guard_addresses(
                parse_target("http://169.254.169.254/latest/meta-data/"),
                allow_private=True,
            )


class FindingFilterTests(unittest.TestCase):
    def test_out_of_scope_findings_are_dropped(self):
        policy = ScopePolicy.from_entries(["example.com"])
        findings = [
            Finding(title="inside", target="https://app.example.com/x"),
            Finding(title="outside", target="https://evil.test/x"),
        ]
        kept = guard_report_targets(findings, policy)
        self.assertEqual([finding.title for finding in kept], ["inside"])

    def test_ip_findings_without_scheme_are_kept(self):
        policy = ScopePolicy.from_entries(["127.0.0.1"])
        findings = [
            Finding(title="open port", target="127.0.0.1:8765"),
            Finding(title="other", target="10.9.9.9"),
        ]
        kept = guard_report_targets(findings, policy)
        self.assertEqual([finding.title for finding in kept], ["open port"])


if __name__ == "__main__":
    unittest.main()
