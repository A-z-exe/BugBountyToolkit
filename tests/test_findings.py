"""Tests for the finding model and aggregation."""
import unittest

from bbt.findings import Finding, FindingsStore


class FindingsTests(unittest.TestCase):
    def test_deduplication(self):
        store = FindingsStore()
        self.assertTrue(store.add(Finding(title="XSS", target="http://a")))
        self.assertFalse(store.add(Finding(title="XSS", target="http://a")))
        self.assertEqual(len(store), 1)

    def test_counts(self):
        store = FindingsStore()
        store.add(Finding(title="A", severity="high", target="t"))
        store.add(Finding(title="B", severity="high", target="t"))
        store.add(Finding(title="C", severity="info", target="t"))
        counts = store.counts()
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["info"], 1)
        self.assertEqual(counts["critical"], 0)

    def test_sorting_puts_critical_first(self):
        store = FindingsStore()
        store.add(Finding(title="low", severity="low", target="t"))
        store.add(Finding(title="crit", severity="critical", target="t"))
        ordered = store.sorted()
        self.assertEqual(ordered[0].severity, "critical")

    def test_invalid_severity_defaults_to_info(self):
        self.assertEqual(Finding(title="x", severity="bogus").severity, "info")

    def test_retain_filters_items_and_resets_dedup_keys(self):
        store = FindingsStore()
        store.add(Finding(title="inside", target="https://a.test"))
        store.add(Finding(title="outside", target="https://b.test"))
        removed = store.retain(lambda finding: "a.test" in finding.target)
        self.assertEqual(removed, 1)
        self.assertEqual([finding.title for finding in store], ["inside"])
        self.assertTrue(store.add(Finding(title="outside", target="https://b.test")))


if __name__ == "__main__":
    unittest.main()
