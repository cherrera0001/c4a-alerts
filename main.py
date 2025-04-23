import os
import requests

def send_telegram(msg):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"}
    requests.post(url, data=payload)

# Simple alerta CVE reciente
cve = requests.get("https://cve.circl.lu/api/last").json()[0]
mensaje = f"*Nuevo CVE:* {cve['id']}\n📝 {cve['summary']}"
send_telegram(mensaje)
