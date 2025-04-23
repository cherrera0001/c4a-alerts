import os
import requests
from collector import get_latest_cves

def send_telegram(msg):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": msg,
        # "parse_mode": "MarkdownV2"  # puedes activarlo si el mensaje está bien escapado
    }

    print(f"🟡 Enviando mensaje al bot:\n{msg}\n")

    try:
        response = requests.post(url, data=payload, timeout=10)
        result = response.json()
        if not result.get("ok"):
            print(f"❌ Error en respuesta de Telegram: {result}")
    except Exception as e:
        print(f"❌ Error al enviar mensaje a Telegram: {e}")

# Obtener CVEs y enviar alertas
cve_alerts = get_latest
