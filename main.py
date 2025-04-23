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
        "parse_mode": "Markdown"  # usar Markdown plano es más tolerante que MarkdownV2
    }

    print(f"📤 Enviando mensaje al bot:\n{msg}\n")

    try:
        response = requests.post(url, data=payload, timeout=10)
        result = response.json()
        if not result.get("ok"):
            print(f"❌ Telegram rechazó el mensaje: {result}")
        else:
            print("✅ Mensaje enviado correctamente.")
    except Exception as e:
        print(f"❌ Error al enviar mensaje: {e}")

# 🔄 Ejecutar el envío
if __name__ == "__main__":
    cve_alerts = get_latest_cves(limit=1)
    for alert in cve_alerts:
        if alert.strip():
            send_telegram(alert)
        else:
            print("⚠️ Advertencia: el mensaje está vacío y no fue enviado.")
