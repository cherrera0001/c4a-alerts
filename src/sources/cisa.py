import logging
import requests
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timedelta

CISA_ALERTS_RSS = "https://www.cisa.gov/uscert/ncas/alerts.xml"
HEADERS = {"User-Agent": "c4a-alerts-bot/2.0"}

def fetch_cisa_alerts(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Parse CISA alerts from their RSS feed.
    """
    logging.info("[cisa] Fetching CISA alerts...")
    alerts = []
    
    try:
        response = requests.get(CISA_ALERTS_RSS, headers=HEADERS, timeout=15)
        response.raise_for_status()
        
        feed = feedparser.parse(response.content)
        
        # Get current date and date 7 days ago for filtering
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        
        for entry in feed.entries[:limit]:
            pub_date = datetime(*entry.published_parsed[:6])
            
            # Only include alerts from the last 7 days
            if pub_date >= week_ago:
                alerts.append({
                    "title": entry.title,
                    "summary": entry.summary,
                    "url": entry.link,
                    "published": pub_date.isoformat(),
                    "source": "CISA"
                })
        
        return alerts
        
    except Exception as e:
        logging.error(f"❌ Error fetching CISA alerts: {e}")
        return []
