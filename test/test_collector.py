import unittest
from src.collector import get_latest_cves, get_latest_pocs

class TestCollector(unittest.TestCase):
    def test_get_latest_cves_returns_list(self):
        result = get_latest_cves(limit=1)
        self.assertIsInstance(result, list)

    def test_get_latest_pocs_returns_list(self):
        result = get_latest_pocs(limit=1)
        self.assertIsInstance(result, list)
