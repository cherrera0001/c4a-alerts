import logging
import requests
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timedelta

# Feeds RSS de CERTs Nacionales e Internacionales
CERT_FEEDS = {
    "CERT-EU": "https://cert.europa.eu/static/SecurityAdvisories/CERT-EU_SA.xml",  # Europa
    "INCIBE-ES": "https://www.incibe-cert.es/feed/avisos-seguridad/all",            # España
    "JPCERT-JP": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",              # Japón
    "NCSC-UK": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",     # Reino Unido
    "CERT-MX": "https://www.gob.mx/certmx/rss"                                       # México
    # FUTURO: Integrar ANCI Chile, CISA, ENISA si abren API/RSS estable
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36 c4a-alerts-bot/2.0"
    )
}

def fetch_cert_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    """
    Descarga y procesa alertas de los CERTs nacionales e internacionales disponibles vía RSS.
    """
    logging.info("[cert] Consultando alertas de los CERTs nacionales e internacionales...")
    all_alerts = []
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    for cert_name, feed_url in CERT_FEEDS.items():
        try:
            response = requests.get(feed_url, headers=HEADERS, timeout=15)
            response.raise_for_status()

            feed = feedparser.parse(response.content)

            for entry in feed.entries:
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])

                # Ignorar alertas de más de 7 días
                if pub_date and pub_date < week_ago:
                    continue

                alert = {
                    "title": getattr(entry, 'title', 'No title'),
                    "summary": getattr(entry, 'summary', ''),
                    "url": getattr(entry, 'link', ''),
                    "published": pub_date.isoformat() if pub_date else "Unknown",
                    "source": cert_name
                }
                all_alerts.append(alert)

                if len(all_alerts) >= limit:
                    logging.info(f"[cert] Se alcanzó el límite configurado de {limit} alertas.")
                    return all_alerts

        except requests.exceptions.HTTPError as e:
            logging.error(f"❌ HTTP error ({response.status_code}) en {cert_name}: {e}")
            continue
        except requests.exceptions.Timeout:
            logging.error(f"⏳ Timeout al conectar con {cert_name}")
            continue
        except requests.exceptions.ConnectionError:
            logging.error(f"❌ Error de conexión a {cert_name}")
            continue
        except Exception as e:
            logging.error(f"❌ Error inesperado procesando {cert_name}: {e}")
            continue

    logging.info(f"[cert] Total alertas recopiladas: {len(all_alerts)}")
    return all_alerts
