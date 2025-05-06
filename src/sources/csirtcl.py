import feedparser
from datetime import datetime
from typing import List, Dict
from ..logger import info, warning
from bs4 import BeautifulSoup


def fetch_csirt_cl_alerts(limit: int = 15) -> List[Dict]:
    """
    Obtiene alertas de seguridad desde el RSS de CSIRT Chile.
    Se asegura de incluir entradas aunque solo tengan imagen.
    """
    alerts = []
    url = "https://csirt.gob.cl/rss/alertas"

    try:
        feed = feedparser.parse(url)
        total = len(feed.entries)
        if total == 0:
            warning("[CSIRT Chile] El feed no contiene entradas.")
            return []

        for entry in feed.entries[:limit]:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            guid = entry.get("id", link)

            # Publicación
            try:
                published = datetime(*entry.published_parsed[:6])
            except Exception:
                published = datetime.now()

            # Parsear descripción (imagen embebida)
            soup = BeautifulSoup(entry.get("description", ""), "html.parser")
            img = soup.find("img")
            description = img["src"] if img and img.has_attr("src") else "Sin descripción visible."

            # Severidad básica desde título
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

        info(f"[CSIRT Chile] {len(alerts)} alertas obtenidas correctamente de {total} entradas RSS.")

    except Exception as e:
        warning(f"[CSIRT Chile] Error al obtener o procesar el feed: {str(e)}")

    return alerts
