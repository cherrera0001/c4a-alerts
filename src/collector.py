import logging
import requests
from datetime import datetime
from typing import List
from src.utils import escape_markdown, validate_url

CVE_API_URL = "https://cve.circl.lu/api/last"
POC_SOURCES = [
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/main/latest.json",
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/latest.json",
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/gh-pages/latest.json",
]


def get_latest_cves(limit: int = 5) -> List[str]:
    """
    Recupera los últimos CVEs desde CIRCL API que sean del año actual
    y tengan una severidad CVSS >= 7.0.
    """
    current_year = str(datetime.now().year)

    try:
        response = requests.get(CVE_API_URL, timeout=10)
        response.raise_for_status()
        cves = response.json()

        if not isinstance(cves, list):
            logging.warning("⚠️ Respuesta inesperada de la API de CIRCL.")
            return []

        alerts = []
        for cve in cves:
            cve_id = cve.get("cveMetadata", {}).get("cveId", "")
            if not cve_id.startswith(f"CVE-{current_year}"):
                continue

            cvss = cve.get("containers", {}).get("cna", {}).get("metrics", [{}])[0].get("cvssV3", {}).get("baseScore", 0)
            if not isinstance(cvss, (int, float)) or cvss < 7.0:
                continue

            description = (
                cve.get("containers", {})
                .get("cna", {})
                .get("descriptions", [{}])[0]
                .get("value", "Sin descripción")
            )

            alert = (
                f"🚨 *Nuevo CVE:* `{escape_markdown(cve_id)}`\n"
                f"📝 {escape_markdown(description)}\n"
                f"📊 CVSS: {cvss}"
            )
            alerts.append(alert)

            if len(alerts) >= limit:
                break

        return alerts or ["✅ No se encontraron vulnerabilidades críticas recientes."]

    except Exception as e:
        logging.error(f"❌ Error al consultar CVEs: {e}")
        return [f"⚠️ Error al consultar CVEs: {str(e)}"]


def get_latest_pocs(limit: int = 5) -> List[str]:
    """
    Recupera PoCs recientes desde las fuentes configuradas (PoC-in-GitHub),
    validando los enlaces y retornando mensajes formateados.
    """
    alerts = []

    for url in POC_SOURCES:
        try:
            logging.info(f"🔍 Intentando fuente: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                continue

            data = response.json()
            if not isinstance(data, list):
                continue

            for item in data:
                poc_url = item.get("html_url", "")
                if not validate_url(poc_url):
                    continue

                cve_id = item.get("cve_id", "Sin ID")
                description = item.get("description", "Sin descripción")

                alert = (
                    f"🧪 *PoC GitHub*\n"
                    f"🔍 {escape_markdown(cve_id)}\n"
                    f"📝 {escape_markdown(description)}\n"
                    f"🔗 {poc_url}"
                )
                alerts.append(alert)

                if len(alerts) >= limit:
                    return alerts

        except Exception as e:
            logging.warning(f"⚠️ Error al consultar {url}: {e}")

    return alerts or ["✅ No se encontraron PoCs válidos recientes."]
