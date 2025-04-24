import unittest
from src.secure_storage import encrypt_data, decrypt_data

class TestSecureStorage(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef0123456789abcdef'
        self.data = "mensaje de prueba"

    def test_encrypt_and_decrypt(self):
        encrypted = encrypt_data(self.data, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(decrypted, self.data)
