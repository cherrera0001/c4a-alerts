import logging
import requests
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timedelta

CERT_FEEDS = {
    "CISA-US": "https://www.cisa.gov/uscert/ncas/alerts.xml",
    "CERT-FR": "https://www.cert.ssi.gouv.fr/feed/",
    "CERT-BR": "https://www.cert.br/rss/feed/alertas/",
    "CERT-EU": "https://cert.europa.eu/static/SecurityAdvisories/CERT-EU_SA.xml",
    "CERT-MX": "https://www.gob.mx/certmx/rss",
    "JPCERT-JP": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
    "NCSC-UK": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "ICS-CERT": "https://www.cisa.gov/uscert/ics/alerts.xml"
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/115.0.0.0 Safari/537.36 c4a-alerts-bot/3.0"
    )
}

def fetch_cert_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    logging.info("[cert] Consultando alertas de los CERTs...")
    all_alerts = []
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=2)
    session.mount('https://', adapter)  # ✅ Solo HTTPS

    for cert_name, feed_url in CERT_FEEDS.items():
        try:
            logging.info(f"[cert] Consultando feed de {cert_name}")
            response = session.get(feed_url, headers=HEADERS, timeout=15)
            response.raise_for_status()

            feed = feedparser.parse(response.content)
            if feed.bozo:
                logging.warning(f"⚠️ Feed malformado en {cert_name}: {feed.bozo_exception}")
                continue

            for entry in feed.entries:
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])

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
        except requests.exceptions.Timeout:
            logging.error(f"⏳ Timeout al conectar con {cert_name}")
        except requests.exceptions.ConnectionError:
            logging.error(f"❌ Error de conexión a {cert_name}")
        except Exception as e:
            logging.error(f"❌ Error inesperado procesando {cert_name}: {e}")

    logging.info(f"[cert] Total alertas recopiladas: {len(all_alerts)}")
    return all_alerts
