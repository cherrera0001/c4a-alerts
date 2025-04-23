import os
import requests
from collector import get_latest_cves

def send_telegram(msg):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"}
    requests.post(url, data=payload)

# Obtener CVEs y enviar alertas
cve_alerts = get_latest_cves(limit=1)
for alert in cve_alerts:
    send_telegram(alert)
