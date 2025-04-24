import os
import logging
import requests
from dotenv import load_dotenv
from src.collector import get_latest_cves, get_latest_pocs, escape_markdown

# Configuración
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
load_dotenv()

def send_telegram(msg: str) -> None:
    """
    Envía un mensaje a Telegram utilizando el bot y chat configurados.
    """
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")

    if not token or not chat_id:
        logging.error("❌ TELEGRAM_TOKEN o CHAT_ID no configurados.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": escape_markdown(msg),
        "parse_mode": "MarkdownV2"
    }

    try:
        response = requests.post(url, data=payload, timeout=10)
        result = response.json()
        if not result.get("ok"):
            logging.error(f"❌ Telegram rechazó el mensaje: {result}")
        else:
            logging.info("📬 Mensaje enviado correctamente a Telegram.")
    except Exception as e:
        logging.error(f"❌ Error al enviar mensaje: {e}")

def run_alerts() -> None:
    """
    Ejecuta el flujo principal: obtiene CVEs y PoCs, y los envía si son válidos.
    """
    cve_alerts = get_latest_cves(limit=5)
    poc_alerts = get_latest_pocs(limit=5)
    all_alerts = cve_alerts + poc_alerts

    for alert in all_alerts:
        if alert.strip() and "Sin ID" not in alert and "Sin descripción" not in alert:
            send_telegram(alert)
        else:
            logging.info("ℹ️ Alerta ignorada (vacía o sin datos relevantes).")

if __name__ == "__main__":
    run_alerts()
