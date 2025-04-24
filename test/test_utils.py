import unittest
from src.utils import escape_markdown, validate_url, sanitize_cve_id


class TestUtils(unittest.TestCase):

    def test_escape_markdown(self):
        original = "CVE-2024-1234 (Critical)!"
        escaped = escape_markdown(original)
        self.assertIn("\\(", escaped)
        self.assertIn("\\)", escaped)
        self.assertIn("\\!", escaped)

    def test_validate_url_success(self):
        self.assertTrue(validate_url("https://www.google.com"))

    def test_validate_url_fail(self):
        self.assertFalse(validate_url("http://invalid.localdomain"))

    def test_sanitize_cve_id_valid(self):
        valid_id = "CVE-2024-12345"
        self.assertEqual(sanitize_cve_id(valid_id), valid_id)

    def test_sanitize_cve_id_invalid(self):
        invalid_id = "CVE-ABC-XYZ"
        self.assertEqual(sanitize_cve_id(invalid_id), "INVALID_CVE")


if __name__ == "__main__":
    unittest.main()
