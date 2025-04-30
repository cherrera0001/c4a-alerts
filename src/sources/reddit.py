import os
import requests
import logging
from datetime import datetime, timedelta
from typing import List, Dict

REDDIT_API_URL = "https://oauth.reddit.com/r/netsec/new"
KEYWORDS = ["0day", "cve", "exploit", "vulnerability", "bypass", "rce"]

# Establecer User-Agent seguro (obligatorio para Reddit)
DEFAULT_USER_AGENT = "C4A-Alerts/1.0 (by /u/Proud_Introduction66)"
USER_AGENT = os.getenv("REDDIT_USER_AGENT", DEFAULT_USER_AGENT)


def get_reddit_token() -> str:
    """
    Realiza autenticación OAuth2 con Reddit y obtiene un access token.
    """
    auth = requests.auth.HTTPBasicAuth(
        os.getenv("REDDIT_CLIENT_ID"),
        os.getenv("REDDIT_CLIENT_SECRET")
    )

    headers = {
        "User-Agent": USER_AGENT
    }

    response = requests.post(
        "https://www.reddit.com/api/v1/access_token",
        auth=auth,
        headers=headers,
        data={"grant_type": "client_credentials"},
        timeout=10
    )

    response.raise_for_status()
    return response.json().get("access_token")


def is_relevant(text: str) -> bool:
    return any(k in text.lower() for k in KEYWORDS)


def fetch_reddit_posts(limit: int = 5) -> List[Dict[str, str]]:
    """
    Consulta posts recientes desde /r/netsec usando Reddit OAuth2.
    """
    logging.info("[reddit] Autenticando con Reddit...")
    try:
        token = get_reddit_token()
    except Exception as e:
        logging.error(f"[reddit] ❌ Error autenticando con Reddit: {e}")
        return []

    headers = {
        "Authorization": f"bearer {token}",
        "User-Agent": USER_AGENT
    }

    try:
        response = requests.get(
            REDDIT_API_URL,
            headers=headers,
            params={"limit": 10},
            timeout=15
        )
        response.raise_for_status()

        posts = response.json().get("data", {}).get("children", [])
        alerts = []

        for post in posts:
            data = post.get("data", {})
            title = data.get("title", "")
            created = datetime.utcfromtimestamp(data.get("created_utc", 0))

            if datetime.utcnow() - created > timedelta(days=1):
                continue

            if is_relevant(title):
                alerts.append({
                    "title": title,
                    "url": f"https://www.reddit.com{data.get('permalink', '')}",
                    "published": created.isoformat(),
                    "source": "Reddit /r/netsec"
                })

                if len(alerts) >= limit:
                    break

        logging.info(f"[reddit] ✅ {len(alerts)} alertas relevantes encontradas.")
        return alerts

    except Exception as e:
        logging.error(f"[reddit] ❌ Error obteniendo posts: {e}")
        return []
