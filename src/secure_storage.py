import logging
import os
import base64
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Set

# Cargar variables de entorno
GIST_ID_RAW = os.getenv("GIST_ID", "")
GIST_ID = GIST_ID_RAW.strip()
GIST_TOKEN = os.getenv("GIST_TOKEN")
ENCRYPTION_KEY_ENV = os.getenv("ENCRYPTION_KEY")

# Configuración de cifrado
if ENCRYPTION_KEY_ENV:
    try:
        ENCRYPTION_KEY = base64.b64decode(ENCRYPTION_KEY_ENV)
        ENCRYPTION_ENABLED = True
    except Exception as e:
        logging.error(f"❌ Error decoding ENCRYPTION_KEY: {e}")
        ENCRYPTION_KEY = None
        ENCRYPTION_ENABLED = False
else:
    logging.warning("⚠️ ENCRYPTION_KEY not set. Secure storage will be disabled.")
    ENCRYPTION_KEY = None
    ENCRYPTION_ENABLED = False

# Configuración de acceso a Gist
if GIST_ID and GIST_TOKEN:
    GIST_API_URL = f"https://api.github.com/gists/{GIST_ID}"
    HEADERS = {
        "Authorization": f"token {GIST_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    GIST_ENABLED = True
else:
    logging.warning("⚠️ GIST_ID or GIST_TOKEN not set. Gist storage will be disabled.")
    GIST_API_URL = None
    HEADERS = None
    GIST_ENABLED = False

def encrypt_data(plain_text: str, key: bytes) -> str:
    if not ENCRYPTION_ENABLED:
        return json.dumps({"data": plain_text})

    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plain_text.encode()) + encryptor.finalize()

    return json.dumps({
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode()
    })

def decrypt_data(encrypted_json: str, key: bytes) -> str:
    try:
        data = json.loads(encrypted_json)
    except json.JSONDecodeError as e:
        logging.error(f"❌ Invalid JSON format: {e}")
        return "[]"

    # Si está en modo no cifrado
    if isinstance(data, dict) and "data" in data:
        return data["data"]

    if not ENCRYPTION_ENABLED:
        logging.error("❌ Cannot decrypt data: encryption is disabled.")
        return "[]"

    try:
        iv = base64.b64decode(data["iv"])
        ct = base64.b64decode(data["ct"])
        tag = base64.b64decode(data["tag"])

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        decrypted_bytes = decryptor.update(ct) + decryptor.finalize()
        decrypted_text = decrypted_bytes.decode()

        # Validar que el desencriptado sea una lista válida
        parsed = json.loads(decrypted_text)
        if not isinstance(parsed, list):
            raise ValueError("Decrypted content is not a list.")

        return decrypted_text

    except Exception as e:
        logging.error(f"❌ Error during decryption: {e}")
        return "[]"

def load_sent_ids() -> Set[str]:
    if not GIST_ENABLED:
        logging.warning("⚠️ Gist storage disabled. Using empty sent IDs set.")
        return set()

    try:
        response = requests.get(GIST_API_URL, headers=HEADERS, timeout=10)
        response.raise_for_status()
        files = response.json().get("files", {})

        if "alerts.json" not in files:
            logging.warning("⚠️ alerts.json not found in Gist. Starting with empty history.")
            return set()

        gist_content = files["alerts.json"].get("content", "[]")
        decrypted = decrypt_data(gist_content, ENCRYPTION_KEY)
        ids = json.loads(decrypted)

        if not isinstance(ids, list):
            logging.error("❌ Decrypted data is not a list. Resetting history.")
            return set()

        return set(ids)

    except Exception as e:
        logging.error(f"❌ Failed to load sent IDs from Gist: {e}")
        return set()

def save_sent_ids(ids: Set[str]) -> None:
    if not GIST_ENABLED:
        logging.warning("⚠️ Gist storage disabled. Sent IDs not saved.")
        return

    try:
        plain = json.dumps(list(ids))
        encrypted = encrypt_data(plain, ENCRYPTION_KEY)

        payload = {
            "files": {
                "alerts.json": {
                    "content": encrypted
                }
            }
        }

        response = requests.patch(GIST_API_URL, headers=HEADERS, json=payload, timeout=10)
        response.raise_for_status()
        logging.info("✅ History updated successfully in Gist.")

    except Exception as e:
        logging.error(f"❌ Error saving history to Gist: {e}")
