import os
import requests
from collector import get_latest_cves, get_latest_pocs

def send_telegram(msg):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": msg,
        "parse_mode": "Markdown"
    }

    print(f"📤 Enviando mensaje al bot:\n{msg}\n")

    try:
        response = requests.post(url, data=payload, timeout=10)
        result = response.json()
        print("📬 Respuesta Telegram:", result)
        if not result.get("ok"):
            print(f"❌ Telegram rechazó el mensaje: {result}")
    except Exception as e:
        print(f"❌ Error al enviar mensaje a Telegram: {e}")

if __name__ == "__main__":
    alerts = get_latest_cves(limit=1) + get_latest_pocs(limit=2)
    for alert in alerts:
        if alert.strip():
            send_telegram(alert)
        else:
            print("⚠️ Advertencia: mensaje vacío, no enviado.")
