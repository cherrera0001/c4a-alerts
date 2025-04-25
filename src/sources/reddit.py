import logging
import requests
from datetime import datetime, timedelta

HEADERS = {"User-Agent": "c4a-alerts-bot/1.0"}
REDDIT_API = "https://www.reddit.com/r/netsec/new.json"
KEYWORDS = ["0day", "CVE", "exploit", "vulnerability", "bypass", "RCE"]

def is_relevant(text: str) -> bool:
    return any(kw in text.lower() for kw in KEYWORDS)

def fetch_reddit_posts(limit=5):
    logging.info("[reddit] Consultando Reddit...")
    try:
        response = requests.get(REDDIT_API, headers=HEADERS, timeout=10)
        response.raise_for_status()
        posts = response.json().get("data", {}).get("children", [])
        
        alerts = []
        for post in posts:
            data = post["data"]
            title = data.get("title", "")
            url = data.get("url", "")
            created_utc = datetime.utcfromtimestamp(data.get("created_utc", 0))
            if datetime.utcnow() - created_utc > timedelta(days=1):
                continue
            if is_relevant(title):
                alerts.append({"title": title, "url": url, "source": "Reddit"})
            if len(alerts) >= limit:
                break
        return alerts
    except Exception as e:
        logging.error(f"❌ Error al consultar Reddit: {e}")
        return []
