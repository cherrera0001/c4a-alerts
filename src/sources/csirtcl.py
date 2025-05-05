# src/sources/csirtcl.py

import feedparser
from datetime import datetime
from typing import List, Dict
from ..logger import info, warning
from bs4 import BeautifulSoup


def fetch_csirt_cl_alerts(limit: int = 15) -> List[Dict]:
    """
    Obtiene alertas de seguridad desde el feed RSS de CSIRT Chile.
    Retorna una lista de diccionarios normalizados.
    """
    alerts = []
    url = "https://csirt.gob.cl/rss/alertas"

    try:
        feed = feedparser.parse(url)

        for entry in feed.entries[:limit]:
            title = entry.get("title", "")
            raw_description = entry.get("description", "")
            description = BeautifulSoup(raw_description, "html.parser").text.strip()
            link = entry.get("link", "")
            published = entry.get("published_parsed")

            severity = "medium"
            if "crítico" in title.lower():
                severity = "critical"
            elif "alto" in title.lower():
                severity = "high"
            elif "bajo" in title.lower():
                severity = "low"

            alerts.append({
                "id": entry.get("id", link),
                "title": title,
                "description": description or "S/I",
                "published": datetime(*published[:6]) if published else datetime.now(),
                "source": "CSIRT Chile",
                "url": link,
                "severity": severity
            })

        info(f"[CSIRT Chile] {len(alerts)} alertas obtenidas correctamente.")

    except Exception as e:
        warning(f"[CSIRT Chile] Error al obtener alertas: {str(e)}")

    return alerts
