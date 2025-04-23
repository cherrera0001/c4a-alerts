import os
import re
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv

# Configuración
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
load_dotenv()

def escape_markdown(text):
    escape_chars = r"_*[]()~`>#+-=|{}.!\\"
    return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", text)

def validate_url(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException as e:
        logging.warning(f"⚠️ Enlace inválido: {url} - {e}")
        return False

def get_latest_cves(limit=5):
    url = "https://cve.circl.lu/api/last"
    current_year = str(datetime.now().year)
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        cves = response.json()

        if not isinstance(cves, list):
            logging.warning(f"⚠️ Respuesta inesperada: {cves}")
            return []

        alerts = []
        for cve in cves:
            cve_id = cve.get("cveMetadata", {}).get("cveId", "")
            if not cve_id.startswith(f"CVE-{current_year}"):
                continue

            cvss = cve.get("containers", {}).get("cna", {}).get("metrics", [{}])[0].get("cvssV3", {}).get("baseScore", 0)
            if cvss < 7.0:
                continue

            description = (
                cve.get("containers", {})
                .get("cna", {})
                .get("descriptions", [{}])[0]
                .get("value", "Sin descripción")
            )

            alerts.append(
                f"🚨 *Nuevo CVE:* `{escape_markdown(cve_id)}`\n"
                f"📝 {escape_markdown(description)}\n"
                f"📊 CVSS: {cvss}"
            )

            if len(alerts) >= limit:
                break

        return alerts if alerts else ["✅ No se encontraron vulnerabilidades críticas recientes."]
    except Exception as e:
        logging.error(f"❌ Error al consultar CVEs: {e}")
        return [f"⚠️ Error al consultar CVEs: {str(e)}"]

def get_latest_pocs(limit=5):
    sources = [
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/main/latest.json",
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/latest.json",
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/gh-pages/latest.json",
    ]
    alerts = []

    for url in sources:
        try:
            logging.info(f"🔍 Intentando fuente: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                continue
            data = response.json()
            if not isinstance(data, list):
                continue

            for item in data:
                poc_url = item.get('html_url', '')
                if not validate_url(poc_url):
                    continue

                alert = (
                    f"🧪 *PoC GitHub*\n"
                    f"🔍 {escape_markdown(item.get('cve_id', 'Sin ID'))}\n"
                    f"📝 {escape_markdown(item.get('description', 'Sin descripción'))}\n"
                    f"🔗 {poc_url}"
                )
                alerts.append(alert)
                if len(alerts) >= limit:
                    break
            break  # Detener intentos si una fuente funcionó
        except Exception as e:
            logging.warning(f"⚠️ Error al consultar {url}: {e}")

    return alerts if alerts else ["✅ No se encontraron PoCs válidos recientes."]
