import logging
import requests
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timedelta

# National CERTs RSS feeds
CERT_FEEDS = {
    "EU-CERT": "https://cert.europa.eu/cert/Data/rss/rss.xml",
    "INCIBE-ES": "https://www.incibe.es/feed/avisos-seguridad/all",
    "JPCERT": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
    "NCSC-UK": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"
}

HEADERS = {"User-Agent": "c4a-alerts-bot/2.0"}

def fetch_cert_alerts(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Parse alerts from national CERTs.
    """
    logging.info("[cert] Fetching alerts from national CERTs...")
    all_alerts = []
    
    # Get current date and date 7 days ago for filtering
    now = datetime.now()
    week_ago = now - timedelta(days=7)
    
    for cert_name, feed_url in CERT_FEEDS.items():
        try:
            response = requests.get(feed_url, headers=HEADERS, timeout=15)
            if response.status_code != 200:
                logging.warning(f"⚠️ Failed to fetch {cert_name} feed: HTTP {response.status_code}")
                continue
                
            feed = feedparser.parse(response.content)
            
            for entry in feed.entries[:3]:  # Limit to 3 entries per CERT
                # Try to parse the published date
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])
                
                # Skip entries older than a week
                if pub_date and pub_date < week_ago:
                    continue
                    
                all_alerts.append({
                    "title": entry.title,
                    "summary": entry.summary if hasattr(entry, 'summary') else "",
                    "url": entry.link,
                    "published": pub_date.isoformat() if pub_date else "Unknown",
                    "source": cert_name
                })
                
                if len(all_alerts) >= limit:
                    return all_alerts
                    
        except Exception as e:
            logging.error(f"❌ Error fetching {cert_name} alerts: {e}")
    
    return all_alerts
