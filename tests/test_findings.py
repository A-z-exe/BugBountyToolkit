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


if __name__ == "__main__":
    unittest.main()
