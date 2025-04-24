import os
import requests

# Obtener valores desde variables de entorno
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

mensaje = "🚨 *Prueba directa desde script local*"

payload = {
    "chat_id": CHAT_ID,
    "text": mensaje,
    "parse_mode": "Markdown"
}

url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

print(f"📤 Enviando a {url} con payload:\n{payload}\n")

try:
    response = requests.post(url, data=payload, timeout=10)
    print("📬 Status code:", response.status_code)
    print("📬 Respuesta:", response.json())
except Exception as e:
    print(f"❌ Error en el envío: {e}")
