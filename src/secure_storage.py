import os
import json
import base64
import logging
import requests
from typing import Set
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Environment variables
GIST_ID = os.getenv("GIST_ID", "").strip()
GIST_TOKEN = os.getenv("GIST_TOKEN", "").strip()
ENCRYPTION_KEY_ENV = os.getenv("ENCRYPTION_KEY")

# Gist API setup
GIST_API_URL = f"https://api.github.com/gists/{GIST_ID}" if GIST_ID else None
HEADERS = {
    "Authorization": f"token {GIST_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
} if GIST_TOKEN else None

# Encryption setup
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
        return data["data"]  # Plain storage fallback

    if not ENCRYPTION_ENABLED:
        logging.error("❌ Cannot decrypt data: encryption disabled.")
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
    """
    Load previously sent alert IDs securely from GitHub Gist.
    """
    if not GIST_API_URL or not HEADERS:
        logging.warning("⚠️ Gist configuration missing. Returning empty set.")
        return set()

    try:
        response = requests.get(GIST_API_URL, headers=HEADERS, timeout=15)
        response.raise_for_status()
        files = response.json().get("files", {})
        content = files.get("alerts.json", {}).get("content", None)

        if not content:
            logging.info("ℹ️ No previous alerts found. Initializing.")
            return set()

        decrypted = decrypt_data(content, ENCRYPTION_KEY)
        return set(json.loads(decrypted))
    except Exception as e:
        logging.error(f"❌ Failed to load sent IDs from Gist: {e}")
        return set()

def save_sent_ids(ids: Set[str]) -> None:
    """
    Save the set of sent alert IDs securely to GitHub Gist.
    """
    if not GIST_API_URL or not HEADERS:
        logging.warning("⚠️ Gist configuration missing. Sent IDs not saved.")
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
        response = requests.patch(GIST_API_URL, headers=HEADERS, json=payload, timeout=15)
        response.raise_for_status()
        logging.info("✅ Successfully updated sent IDs in Gist.")
    except Exception as e:
        logging.error(f"❌ Error saving sent IDs to Gist: {e}")
