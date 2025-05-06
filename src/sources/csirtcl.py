
import requests
import socket
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from datetime import datetime
from typing import List, Dict
from ..logger import info, warning, error

def fetch_csirt_cl_alerts(limit: int = 15) -> List[Dict]:
    url = "https://csirt.gob.cl/rss/alertas"
    fallback_file = "fallback_csirt_alertas.xml"
    alerts = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/rss+xml,application/xml",
        "Referer": "https://csirt.gob.cl/"
    }

    try:
        socket.gethostbyname("csirt.gob.cl")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        xml_content = response.text
        with open(fallback_file, "w", encoding="utf-8") as f:
            f.write(xml_content)
        info("[CSIRT Chile] Feed descargado y respaldado localmente.")

    except requests.exceptions.HTTPError as http_err:
        warning(f"[CSIRT Chile] HTTP error: {http_err} — Intentando leer respaldo.")
    except Exception as e:
        warning(f"[CSIRT Chile] Fallo al descargar el feed: {e}. Intentando leer archivo local...")
        try:
            with open(fallback_file, "r", encoding="utf-8") as f:
                xml_content = f.read()
            info("[CSIRT Chile] Feed cargado desde respaldo local.")
        except Exception as local_err:
            error(f"[CSIRT Chile] No se pudo leer archivo local de respaldo: {local_err}")
            return []

    try:
        xml_content = xml_content.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        root = ET.fromstring(xml_content)
        items = root.findall(".//item")

        if not items:
            warning("[CSIRT Chile] El feed fue leído pero no contiene entradas válidas.")
            return []

        for item in items[:limit]:
            try:
                title = item.findtext("title", default="").strip() or "Sin título"
                link = item.findtext("link", default="").strip()
                guid = item.findtext("guid", default=link).strip()
                pub_date_raw = item.findtext("pubDate", default="").strip()

                published = None
                for fmt in ["%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"]:
                    try:
                        published = datetime.strptime(pub_date_raw, fmt)
                        break
                    except Exception:
                        continue
                if not published:
                    warning(f"[CSIRT Chile] pubDate inválido: {pub_date_raw}. Usando fecha actual.")
                    published = datetime.now()

                raw_description = item.findtext("description", default="").strip()
                soup = BeautifulSoup(raw_description, "html.parser")

                image_urls = [img["src"] for img in soup.find_all("img") if img.get("src")]
                desc_text = soup.get_text(strip=True)
                if image_urls and not desc_text:
                    description = image_urls[0]
                elif image_urls and desc_text:
                    description = f"{desc_text}\n\nImagen: {image_urls[0]}"
                elif desc_text:
                    description = desc_text
                else:
                    description = "Sin descripción visible."

                categories = [cat.text.strip() for cat in item.findall("category")]

                severity = "medium"
                t = title.lower()
                if "crítico" in t or "critical" in t:
                    severity = "critical"
                elif "alto" in t or "high" in t:
                    severity = "high"
                elif "bajo" in t or "low" in t:
                    severity = "low"

                alerts.append({
                    "id": guid,
                    "title": title,
                    "description": description,
                    "url": link,
                    "published": published.isoformat(),
                    "severity": severity,
                    "source": "CSIRT Chile",
                    "categories": categories,
                })

            except Exception as item_err:
                warning(f"[CSIRT Chile] Error al procesar item: {item_err}")

        info(f"[CSIRT Chile] {len(alerts)} alertas obtenidas correctamente.")
        return alerts

    except Exception as parse_err:
        error(f"[CSIRT Chile] Error al parsear feed: {parse_err}")
        return []
