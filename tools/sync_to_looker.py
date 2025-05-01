import os
import json
import logging
from datetime import datetime
import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
from pathlib import Path
import base64

# Cargar variables de entorno
load_dotenv()

SHEET_ID = os.getenv("LOOKER_SHEET_ID")
LOOKER_KEY_B64 = os.getenv("LOOKER_KEY_B64")

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
TEMP_KEY_PATH = "tools/sync/looker-key.json"


def decode_looker_key():
    if not LOOKER_KEY_B64:
        logging.error("❌ LOOKER_KEY_B64 no está configurado.")
        return False

    Path("tools/sync").mkdir(parents=True, exist_ok=True)
    try:
        with open(TEMP_KEY_PATH, "wb") as f:
            f.write(base64.b64decode(LOOKER_KEY_B64))
        return True
    except Exception as e:
        logging.error(f"❌ Error decodificando clave Looker: {e}")
        return False


def send_to_looker(alerts):
    if not SHEET_ID or not decode_looker_key():
        logging.error("❌ Faltan variables LOOKER_SHEET_ID o LOOKER_KEY_B64 inválida.")
        return

    creds = Credentials.from_service_account_file(
        TEMP_KEY_PATH,
        scopes=SCOPES
    )
    client = gspread.authorize(creds)

    try:
        sheet = client.open_by_key(SHEET_ID).sheet1
    except Exception as e:
        logging.error(f"❌ Error al abrir la hoja: {e}")
        return

    rows = []
    for alert in alerts:
        rows.append([
            alert.get("published", datetime.utcnow().isoformat()),
            alert.get("source", "N/A"),
            alert.get("title", "N/A"),
            alert.get("description", "")[:100],
            alert.get("url", "")
        ])

    try:
        sheet.append_rows(rows, value_input_option="USER_ENTERED")
        logging.info(f"✅ {len(rows)} registros enviados exitosamente a Looker Studio (Google Sheets).")
    except Exception as e:
        logging.error(f"❌ Error enviando datos a la hoja: {e}")
