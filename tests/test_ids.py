"""Tests for identifier extraction used by BOLA/IDOR checks."""
import unittest

from bbt.ids import collect_ids, extract_ids, ids_from_url, looks_like_id


class IdExtractionTests(unittest.TestCase):
    def test_extracts_prefixed_id_from_text(self):
        self.assertIn("exp_6c2d91", extract_ids('{"export_id": "exp_6c2d91"}'))

    def test_extracts_uuid(self):
        value = "550e8400-e29b-41d4-a716-446655440000"
        self.assertIn(value, extract_ids('"id": "%s"' % value))

    def test_extracts_numeric_json_id(self):
        self.assertIn("4242", extract_ids('{"user_id": 4242, "name": "x"}'))

    def test_ids_from_url_path_and_query(self):
        url = "https://example.com/api/exports/exp_6c2d91?user_id=42&q=hello"
        values = ids_from_url(url)
        self.assertIn("exp_6c2d91", values)
        self.assertIn("42", values)
        self.assertNotIn("hello", values)

    def test_collect_ids_deduplicates(self):
        values = collect_ids(
            [
                "https://example.com/users/42",
                '{"id": 42, "other": "exp_6c2d91"}',
            ]
        )
        self.assertEqual(values.count("42"), 1)
        self.assertIn("exp_6c2d91", values)

    def test_looks_like_id(self):
        self.assertTrue(looks_like_id("42"))
        self.assertTrue(looks_like_id("exp_6c2d91"))
        self.assertFalse(looks_like_id("about"))
        self.assertFalse(looks_like_id("1234567890123"))


if __name__ == "__main__":
    unittest.main()
