import os
import json
import logging
from datetime import datetime
from dotenv import load_dotenv
import gspread
from google.oauth2.service_account import Credentials

# Cargar variables de entorno
load_dotenv()

SHEET_ID = os.getenv("LOOKER_SHEET_ID")
SERVICE_ACCOUNT_FILE = os.getenv("LOOKER_KEY_PATH", "looker-key.json")
JSON_PATH = "alerts_history.json"

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def load_alerts():
    if not os.path.exists(JSON_PATH):
        logging.warning(f"[Looker] Archivo {JSON_PATH} no encontrado.")
        return []

    with open(JSON_PATH, "r") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError as e:
            logging.error(f"[Looker] ❌ Error al parsear JSON: {e}")
            return []


def send_to_looker(alerts):
    if not SHEET_ID or not os.path.exists(SERVICE_ACCOUNT_FILE):
        logging.error("❌ LOOKER_SHEET_ID o la clave de servicio JSON no están configuradas correctamente.")
        return

    # Autenticación segura con Google Sheets
    creds = Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=SCOPES
    )
    client = gspread.authorize(creds)

    try:
        sheet = client.open_by_key(SHEET_ID).sheet1  # Primera pestaña
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


if __name__ == "__main__":
    alerts = load_alerts()
    if alerts:
        send_to_looker(alerts)
    else:
        logging.warning("[Looker] No hay datos para exportar.")
