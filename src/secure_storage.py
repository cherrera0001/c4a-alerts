import os
import json
import base64
import logging
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Set

# Cargar variables de entorno
GIST_ID_RAW = os.getenv("GIST_ID", "")
GIST_ID = GIST_ID_RAW.strip() if GIST_ID_RAW else ""
GIST_TOKEN = os.getenv("GIST_TOKEN", "").strip()
ENCRYPTION_KEY_ENV = os.getenv("ENCRYPTION_KEY", "").strip()

# Inicializar flags
GIST_ENABLED = bool(GIST_ID and GIST_TOKEN)
ENCRYPTION_ENABLED = False

# Intentar decodificar clave de cifrado
if ENCRYPTION_KEY_ENV:
    try:
        ENCRYPTION_KEY = base64.b64decode(ENCRYPTION_KEY_ENV)
        ENCRYPTION_ENABLED = True
    except Exception as e:
        logging.error(f"❌ Error decoding ENCRYPTION_KEY: {e}")
        ENCRYPTION_KEY = None

# Configurar Gist API
if GIST_ENABLED:
    GIST_API_URL = f"https://api.github.com/gists/{GIST_ID}"
    HEADERS = {
        "Authorization": f"token {GIST_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
else:
    GIST_API_URL = None
    HEADERS = None


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
    data = json.loads(encrypted_json)

    if "data" in data:
        return data["data"]

    if not ENCRYPTION_ENABLED:
        logging.error("❌ Cannot decrypt data: encryption is disabled.")
        return "[]"

    iv = base64.b64decode(data["iv"])
    ct = base64.b64decode(data["ct"])
    tag = base64.b64decode(data["tag"])

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return (decryptor.update(ct) + decryptor.finalize()).decode()


def load_sent_ids() -> Set[str]:
    if not GIST_ENABLED:
        logging.warning("⚠️ Gist storage disabled. Using empty sent IDs set.")
        return set()

    try:
        response = requests.get(GIST_API_URL, headers=HEADERS, timeout=10)
        response.raise_for_status()
        files = response.json().get("files", {})

        if "alerts.json" not in files:
            logging.warning("⚠️ alerts.json not found in Gist. Creating new history.")
            save_sent_ids(set())
            return set()

        gist_content = files["alerts.json"]["content"]
        decrypted = decrypt_data(gist_content, ENCRYPTION_KEY)
        return set(json.loads(decrypted))
    except Exception as e:
        logging.warning(f"⚠️ Could not load history from Gist: {e}")
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
        logging.info("✅ History updated in Gist.")
    except Exception as e:
        logging.error(f"❌ Error saving history to Gist: {e}")