import os
import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Función para obtener y decodificar el ENCRYPTION_KEY de forma segura
def get_encryption_key():
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise EnvironmentError("❌ ENCRYPTION_KEY no está configurado. Verifica tus Secrets en GitHub.")
    return base64.b64decode(key)

def encrypt_data(data):
    encryption_key = get_encryption_key()
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return {
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
        'nonce': cipher.nonce.hex()
    }

def decrypt_data(enc_data):
    encryption_key = get_encryption_key()
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=bytes.fromhex(enc_data['nonce']))
    plaintext = cipher.decrypt_and_verify(bytes.fromhex(enc_data['ciphertext']), bytes.fromhex(enc_data['tag']))
    return plaintext.decode()

def load_sent_ids():
    try:
        with open("sent_ids.json", "r") as f:
            encrypted = json.load(f)
        data = decrypt_data(encrypted)
        return json.loads(data)
    except (FileNotFoundError, ValueError, KeyError):
        return []

def save_sent_ids(sent_ids):
    data = json.dumps(sent_ids)
    encrypted = encrypt
