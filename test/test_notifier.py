import unittest
from unittest.mock import patch
from src.notifier import send_telegram

class TestNotifier(unittest.TestCase):
    @patch("src.notifier.requests.post")
    def test_send_telegram_success(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"ok": True}
        send_telegram("Mensaje de prueba")
        mock_post.assert_called_once()
