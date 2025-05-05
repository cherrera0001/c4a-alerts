import os
import json
import logging
from datetime import datetime
import gspread
from google.auth import default
from google.auth.transport.requests import Request
from dateutil import parser

SHEET_ID = os.getenv("LOOKER_SHEET_ID")

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

def parse_date(value):
    try:
        if isinstance(value, str):
            dt = parser.parse(value)
            return dt.strftime("%d/%m/%Y %H:%M:%S")
        elif isinstance(value, datetime):
            return value.strftime("%d/%m/%Y %H:%M:%S")
    except Exception as e:
        logging.warning(f"⚠️ Error al convertir fecha: {value} ({e})")
    return ""

def send_to_looker(alerts):
    if not SHEET_ID:
        logging.error("❌ LOOKER_SHEET_ID no está configurado.")
        return

    try:
        creds, _ = default(scopes=SCOPES)
        creds.refresh(Request())  # Si es necesario para obtener token
        logging.info("✅ Credenciales cargadas desde Workload Identity Federation.")
    except Exception as e:
        logging.error(f"❌ Error al obtener credenciales por WIF: {e}")
        return

    try:
        client = gspread.authorize(creds)
        sheet = client.open_by_key(SHEET_ID).sheet1
        logging.info("📄 Conexión con Google Sheet establecida exitosamente.")
    except Exception as e:
        logging.error(f"❌ Error al autorizar cliente o abrir la hoja de cálculo: {str(e)}")
        return

    rows = []
    for alert in alerts:
        published = parse_date(alert.get("published"))
        source = alert.get("source") or "N/A"
        title = alert.get("title") or "(Sin título)"
        description = alert.get("description") or title
        url = alert.get("url") or "https://c4a.cl"

        rows.append([published, source, title, description, url])

    try:
        sheet.append_rows(rows, value_input_option="USER_ENTERED")
        logging.info(f"✅ {len(rows)} registros enviados exitosamente a Looker Studio (Google Sheets).")
    except Exception as e:
        logging.error(f"❌ Error enviando datos a la hoja: {e}")
