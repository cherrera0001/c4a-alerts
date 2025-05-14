"""
Test suite for database operations
"""
import unittest
from unittest.mock import patch, MagicMock
from src.database import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    @patch('src.database.create_client')
    def setUp(self, mock_create_client):
        self.mock_client = MagicMock()
        mock_create_client.return_value = self.mock_client
        self.db = DatabaseManager()

    def test_singleton_pattern(self):
        db2 = DatabaseManager()
        self.assertEqual(self.db, db2)

    def test_get_alerts(self):
        mock_data = [{"id": 1, "title": "Test Alert"}]
        self.mock_client.table().select().limit().execute.return_value.data = mock_data
        
        result = self.db.get_alerts(limit=1)
        self.assertEqual(result, mock_data)

    def test_save_alert(self):
        test_alert = {"title": "Test Alert", "description": "Test Description"}
        self.mock_client.table().insert().execute.return_value.data = [test_alert]
        
        result = self.db.save_alert(test_alert)
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()