import logging
import requests
from datetime import datetime, timedelta

# Encabezado mejorado para evitar bloqueos
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36 c4a-alerts-bot/2.0"
    )
}
REDDIT_API = "https://www.reddit.com/r/netsec/new.json"
KEYWORDS = ["0day", "CVE", "exploit", "vulnerability", "bypass", "RCE"]


def is_relevant(text: str) -> bool:
    return any(kw in text.lower() for kw in KEYWORDS)


def fetch_reddit_posts(limit: int = 5):
    """
    Fetches recent relevant posts from r/netsec subreddit.
    """
    logging.info("[reddit] Fetching posts from Reddit...")
    try:
        response = requests.get(REDDIT_API, headers=HEADERS, timeout=10)
        response.raise_for_status()
        posts = response.json().get("data", {}).get("children", [])

        alerts = []
        for post in posts:
            data = post.get("data", {})
            title = data.get("title", "")
            url = data.get("url", "")
            created_utc = datetime.utcfromtimestamp(data.get("created_utc", 0))

            if datetime.utcnow() - created_utc > timedelta(days=1):
                continue
            if is_relevant(title):
                alerts.append({"title": title, "url": url, "source": "Reddit"})
                if len(alerts) >= limit:
                    break

        if not alerts:
            logging.warning("⚠️ No relevant Reddit posts found.")

        return alerts

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 403:
            logging.error("❌ Reddit blocked the request. Consider checking User-Agent or rate limits.")
        else:
            logging.error(f"❌ HTTP error occurred while accessing Reddit: {http_err}")
        return []

    except Exception as e:
        logging.error(f"❌ General error fetching Reddit posts: {e}")
        return []
