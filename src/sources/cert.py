import requests
import logging
import sys
import time
from datetime import datetime, timedelta
import feedparser
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError, Timeout, ConnectionError

def setup_session():
    """
    Configura una sesión de requests con reintentos automáticos y cabecera User-Agent personalizada.
    """
    session = requests.Session()
    # Configurar reintentos automáticos
    adapter = HTTPAdapter(max_retries=3)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    # Establecer User-Agent personalizado
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (compatible; Cert-Feed/1.0; +https://cert.europa.eu/)'
    })
    return session

def fetch_feed(source, url, session, days_limit):
    """
    Descarga y analiza un feed RSS/Atom.

    Parámetros:
        source (str): Nombre de la fuente/CERT.
        url (str): URL del feed RSS/Atom.
        session (requests.Session): Sesión HTTP configurada.
        days_limit (int): Edad máxima de las entradas en días.

    Retorna:
        list of dict: Lista de alertas con campos: titulo, resumen, url, fecha_publicacion, fuente.
    """
    alerts = []
    try:
        logging.info(f"Descargando feed de {source}: {url}")
        response = session.get(url, timeout=10)
        response.raise_for_status()
    except HTTPError as e:
        logging.error(f"Error HTTP al descargar feed de {source}: {e}")
        return alerts
    except Timeout as e:
        logging.error(f"Timeout al descargar feed de {source}: {e}")
        return alerts
    except ConnectionError as e:
        logging.error(f"Error de conexión al descargar feed de {source}: {e}")
        return alerts
    except Exception as e:
        logging.error(f"Error inesperado al descargar feed de {source}: {e}")
        return alerts

    content = response.content
    feed = feedparser.parse(content)
    if feed.bozo:
        logging.warning(f"Feed malformado detectado en {source}: {feed.bozo_exception}")
        # Continuar intentando parsear a pesar del bozo, pero se indica el warning

    # Filtrar por antigüedad
    now = datetime.now()
    threshold = now - timedelta(days=days_limit)
    for entry in feed.entries:
        # Obtener fecha de publicación (intentar published, updated, etc.)
        published = None
        if 'published_parsed' in entry and entry.published_parsed:
            published = datetime.fromtimestamp(time.mktime(entry.published_parsed))
        elif 'updated_parsed' in entry and entry.updated_parsed:
            published = datetime.fromtimestamp(time.mktime(entry.updated_parsed))
        else:
            # Si no hay fecha, saltar la entrada
            logging.warning(f"Entrada sin fecha en feed {source}, título: {entry.get('title', '')}")
            continue
        if published < threshold:
            # Ignorar entradas antiguas
            continue

        # Construir alerta
        title = entry.get('title', '').strip()
        summary = entry.get('summary', '') or entry.get('description', '')
        summary = summary.strip()
        link = entry.get('link', '').strip()
        if not link:
            continue
        alert = {
            'titulo': title,
            'resumen': summary,
            'url': link,
            'fecha_publicacion': published.strftime("%Y-%m-%d %H:%M:%S"),
            'fuente': source
        }
        alerts.append(alert)
    logging.info(f"{source}: Encontradas {len(alerts)} alertas recientes (últimos {days_limit} días).")
    return alerts

def get_cert_alerts(limit=None, days_limit=7):
    """
    Recupera alertas de múltiples feeds RSS de CERTs nacionales e internacionales.

    Parámetros:
        limit (int): Límite dinámico de resultados en total (None para sin límite).
        days_limit (int): Edad máxima de alertas en días.

    Retorna:
        list of dict: Lista combinada de alertas filtradas y limitadas.
    """
    # Diccionario de fuentes y sus feeds RSS/Atom (algunos URLs pueden necesitar verificación)
    sources = {
        'CERT-EU': 'https://cert.europa.eu/publications/security-advisories-rss',
        'CISA-US': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
        'US-CERT-ICS': 'https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml',
        'CERT-FR': 'https://www.cert.ssi.gouv.fr/actualites/rss.xml',  # Ejemplo ANSSI (verificar URL real)
        'CERT-BR': 'https://www.cert.br/feed/',                     # Placeholder (verificar URL real)
        'JPCERT-JP': 'https://www.jpcert.or.jp/rss/news.rdf',       # Placeholder (verificar URL real)
        'NCSC-UK': 'https://www.ncsc.gov.uk/section/keep-up-to-date/ncsc-news/rss',  # Placeholder
        'CERT-MX': 'https://www.cenapred.gob.mx/noticias/rss',      # Placeholder (verificar URL real)
        'KR-CERT': 'https://www.krcert.or.kr/rss',                  # Placeholder (verificar URL real)
    }
    session = setup_session()
    all_alerts = []
    for source, url in sources.items():
        alerts = fetch_feed(source, url, session, days_limit)
        all_alerts.extend(alerts)
    # Ordenar alertas por fecha de publicación (más recientes primero)
    all_alerts.sort(key=lambda x: x['fecha_publicacion'], reverse=True)
    if limit:
        all_alerts = all_alerts[:limit]
    return all_alerts

if __name__ == "__main__":
    # Configurar logging detallado
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    # Obtener alertas (por ejemplo, con límite de 50 resultados)
    alertas = get_cert_alerts(limit=50, days_limit=7)
    # Imprimir alertas con su estructura
    for alerta in alertas:
        print(alerta)

