import os
import json
import base64
import logging
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from typing import Set

load_dotenv()

GIST_ID = os.getenv("GIST_ID")
GIST_TOKEN = os.getenv("GIST_TOKEN")
ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY"))

GIST_API_URL = f"https://api.github.com/gists/{GIST_ID}"
HEADERS = {
    "Authorization": f"token {GIST_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}


def encrypt_data(plain_text: str, key: bytes) -> str:
    """
    Cifra un texto plano utilizando AES-256-GCM y devuelve un JSON codificado.
    """
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
    """
    Descifra un JSON cifrado usando AES-256-GCM y devuelve texto plano.
    """
    data = json.loads(encrypted_json)
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
    Descarga, descifra y carga el historial de IDs enviados desde el Gist.
    """
    try:
        response = requests.get(GIST_API_URL, headers=HEADERS, timeout=10)
        response.raise_for_status()
        gist_content = response.json()["files"]["alerts.json"]["content"]
        decrypted = decrypt_data(gist_content, ENCRYPTION_KEY)
        return set(json.loads(decrypted))
    except Exception as e:
        logging.warning(f"⚠️ No se pudo cargar el historial del Gist: {e}")
        return set()


def save_sent_ids(ids: Set[str]) -> None:
    """
    Cifra y guarda el conjunto de IDs enviados en el Gist.
    """
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
        logging.info("✅ Historial actualizado en Gist.")
    except Exception as e:
        logging.error(f"❌ Error al guardar el historial en Gist: {e}")
