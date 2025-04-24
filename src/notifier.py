import os
import logging
import requests
from dotenv import load_dotenv
from src.utils import escape_markdown

load_dotenv()

def send_telegram(msg: str) -> None:
    """
    Envía un mensaje al bot de Telegram utilizando variables de entorno.
    """
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")

    if not token or not chat_id:
        logging.error("❌ TELEGRAM_TOKEN o CHAT_ID no están configurados.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": escape_markdown(msg),
        "parse_mode": "MarkdownV2"
    }

    try:
        response = requests.post(url, data=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        if not result.get("ok"):
            logging.error(f"❌ Telegram rechazó el mensaje: {result}")
        else:
            logging.info("📬 Mensaje enviado correctamente a Telegram.")
    except requests.RequestException as e:
        logging.error(f"❌ Error al enviar mensaje a Telegram: {e}")
