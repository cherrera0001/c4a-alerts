import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict
from ..logger import info, warning
from bs4 import BeautifulSoup


def fetch_csirt_cl_alerts(limit: int = 15) -> List[Dict]:
    url = "https://csirt.gob.cl/rss/alertas"
    alerts = []

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        root = ET.fromstring(response.content)
        items = root.findall(".//item")

        if not items:
            warning("[CSIRT Chile] El feed fue leído pero no contiene <item>. Revisa el formato XML.")
            return []

        for item in items[:limit]:
            title = item.findtext("title", default="").strip()
            link = item.findtext("link", default="").strip()
            guid = item.findtext("guid", default=link).strip()

            pub_date_raw = item.findtext("pubDate", default="")
            try:
                published = datetime.strptime(pub_date_raw, "%a, %d %b %Y %H:%M:%S %z")
            except Exception:
                published = datetime.now()

            raw_description = item.findtext("description", default="").strip()
            soup = BeautifulSoup(raw_description, "html.parser")
            img = soup.find("img")
            description = img["src"] if img and img.has_attr("src") else "Sin descripción visible."

            # Nivel de severidad
            severity = "medium"
            if "crítico" in title.lower():
                severity = "critical"
            elif "alto" in title.lower():
                severity = "high"
            elif "bajo" in title.lower():
                severity = "low"

            alerts.append({
                "id": guid,
                "title": title,
                "description": description,
                "published": published,
                "source": "CSIRT Chile",
                "url": link,
                "severity": severity
            })

        info(f"[CSIRT Chile] {len(alerts)} alertas obtenidas correctamente del XML.")

    except Exception as e:
        warning(f"[CSIRT Chile] Error crítico al parsear el feed XML: {str(e)}")

    return alerts
