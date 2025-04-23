import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()


def escape_markdown(text):
    escape_chars = r"_*[]()~`>#+-=|{}.!\\"
    return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", text)


def send_telegram(msg):
    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("CHAT_ID")
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": escape_markdown(msg),
        "parse_mode": "MarkdownV2"
    }

    print(f"\U0001F4E4 Enviando mensaje al bot:\n{msg}\n")

    try:
        response = requests.post(url, data=payload, timeout=10)
        result = response.json()
        print("\U0001F4EC Respuesta Telegram:", result)
        if not result.get("ok"):
            print(f"\u274C Telegram rechazó el mensaje: {result}")
    except Exception as e:
        print(f"\u274C Error al enviar mensaje a Telegram: {e}")



def get_latest_cves(limit=1):
    url = "https://cve.circl.lu/api/last"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        cves = response.json()

        if not isinstance(cves, list):
            return ["\u26A0\uFE0F Respuesta inesperada de CIRCL: {cves}"]

        alerts = []
        for cve in cves[:limit]:
            cve_id = cve.get("cveMetadata", {}).get("cveId", "Sin ID")
            description = (
                cve.get("containers", {})
                .get("cna", {})
                .get("descriptions", [{}])[0]
                .get("value", "Sin descripción")
            )
            alerts.append(f"\U0001F6A8 *Nuevo CVE:* `{cve_id}`\n\U0001F4DD {description}")

        return alerts

    except Exception as e:
        return [f"\u26A0\uFE0F Error al consultar CVEs: {str(e)}"]



def get_latest_pocs(limit=2):
    url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/gh-pages/latest.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        if not isinstance(data, list):
            print("\u26A0\uFE0F Formato inesperado en PoCs JSON.")
            return []

        return [
            f"\U0001F9EA *PoC GitHub*\n\U0001F50E {item.get('cve_id', 'Sin ID')}\n\U0001F4DD {item.get('description', 'Sin descripción')}\n\U0001F517 {item.get('html_url', '')}"
            for item in data[:limit]
        ]

    except Exception as e:
        print(f"\u26A0\uFE0F Error al consultar PoCs desde GitHub: {e}")
        return []


if __name__ == "__main__":
    alerts = get_latest_cves(limit=1) + get_latest_pocs(limit=1)
    for alert in alerts:
        if alert.strip():
            send_telegram(alert)
        else:
            print("\u26A0\uFE0F Advertencia: mensaje vacío, no enviado.")