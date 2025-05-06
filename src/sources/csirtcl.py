# src/sources/csirtcl.py

import feedparser
from datetime import datetime
from typing import List, Dict
from ..logger import info, warning
from bs4 import BeautifulSoup

def extract_description(entry) -> str:
    """Extrae una descripción útil incluso si solo hay una imagen en el feed."""
    try:
        soup = BeautifulSoup(entry.get("description", ""), "html.parser")
        img = soup.find("img")
        if img:
            if img.has_attr("src"):
                return f"Sin texto. Ver imagen: {img['src']}"
            elif img.has_attr("alt"):
                return f"Sin texto. Imagen: {img['alt']}"
        return "S/I"
    except Exception:
        return "S/I"

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
            description = extract_description(entry)
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
                "description": description,
                "published": datetime(*published[:6]) if published else datetime.now(),
                "source": "CSIRT Chile",
                "url": link,
                "severity": severity
            })

        info(f"[CSIRT Chile] {len(alerts)} alertas obtenidas correctamente.")

    except Exception as e:
        warning(f"[CSIRT Chile] Error al obtener alertas: {str(e)}")

    return alerts
