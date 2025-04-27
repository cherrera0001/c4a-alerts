import logging
import requests
from datetime import datetime

# Feeds a monitorear
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

# User-Agent personalizado para evitar bloqueos
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/115.0.0.0 Safari/537.36 c4a-alerts-health-check/1.0"
    )
}

def monitor_feeds():
    """
    Monitorea el estado HTTP de los feeds de CERTs configurados.
    """
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=2)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    healthy = 0
    broken = 0

    logging.info(f"🛡️ Iniciando verificación de salud de {len(CERT_FEEDS)} feeds...")

    for cert_name, url in CERT_FEEDS.items():
        try:
            response = session.get(url, headers=HEADERS, timeout=15)
            if response.status_code == 200:
                logging.info(f"✅ {cert_name} OK ({response.status_code})")
                healthy += 1
            else:
                logging.warning(f"⚠️ {cert_name} retornó estado {response.status_code}")
                broken += 1
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ {cert_name} no disponible: {e}")
            broken += 1

    logging.info(f"🏁 Verificación completada: {healthy} feeds OK, {broken} feeds con problemas.")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"Reporte generado en UTC: {now}")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    monitor_feeds()