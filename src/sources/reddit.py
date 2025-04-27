import logging
import random
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict

# Encabezados: Rotación de User-Agents para prevenir bloqueos
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 c4a-alerts-bot/2.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36 c4a-alerts-bot/2.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15 c4a-alerts-bot/2.2",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0 c4a-alerts-bot/2.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1 c4a-alerts-bot/2.4"
]

REDDIT_API = "https://www.reddit.com/r/netsec/new.json"
KEYWORDS = ["0day", "cve", "exploit", "vulnerability", "bypass", "rce"]

def is_relevant(text: str) -> bool:
    """
    Evalúa si el texto contiene alguna palabra clave crítica.
    """
    lower_text = text.lower()
    return any(keyword in lower_text for keyword in KEYWORDS)

def fetch_reddit_posts(limit: int = 5) -> List[Dict[str, str]]:
    """
    Fetches recent relevant posts from r/netsec subreddit.
    """
    logging.info("[reddit] Iniciando consulta a Reddit...")
    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    try:
        start_time = time.time()
        response = requests.get(REDDIT_API, headers=headers, timeout=15)

        # Manejar Rate Limit explícito (429)
        if response.status_code == 429:
            logging.warning("⚠️ Reddit rate limit (429) alcanzado. Esperando para reintentar...")
            time.sleep(10)
            return []

        response.raise_for_status()
        posts = response.json().get("data", {}).get("children", [])

        alerts = []
        for post in posts:
            data = post.get("data", {})
            title = data.get("title", "")
            url = f"https://www.reddit.com{data.get('permalink', '')}"
            created_utc = datetime.utcfromtimestamp(data.get("created_utc", 0))

            # Solo posts de las últimas 24 horas
            if datetime.utcnow() - created_utc > timedelta(days=1):
                continue

            if is_relevant(title):
                alerts.append({
                    "title": title,
                    "url": url,
                    "published": created_utc.isoformat(),
                    "source": "Reddit /r/netsec"
                })

                if len(alerts) >= limit:
                    break

        elapsed = round(time.time() - start_time, 2)
        logging.info(f"[reddit] {len(alerts)} alertas relevantes encontradas en {elapsed}s.")

        if not alerts:
            logging.warning("[reddit] ⚠️ No se encontraron posts relevantes.")

        return alerts

    except requests.exceptions.Timeout:
        logging.error("⏳ Timeout al conectar a Reddit.")
        return []
    except requests.exceptions.ConnectionError:
        logging.error("❌ Error de conexión con Reddit.")
        return []
    except requests.exceptions.HTTPError as e:
        if response.status_code == 403:
            logging.error("❌ Reddit bloqueó el request. Revisa User-Agent o velocidad de consultas.")
        else:
            logging.error(f"❌ Error HTTP accediendo a Reddit: {e}")
        return []
    except Exception as e:
        logging.error(f"❌ Error inesperado accediendo a Reddit: {e}")
        return []
