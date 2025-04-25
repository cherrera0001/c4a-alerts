import logging
import requests
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timedelta

# RSS feeds for various threat intelligence sources
THREAT_FEEDS = {
    "ThreatPost": "https://threatpost.com/feed/",
    "HackerNews": "https://thehackernews.com/feeds/posts/default",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "DarkReading": "https://www.darkreading.com/rss.xml"
}

KEYWORDS = ["vulnerability", "exploit", "cve", "attack", "threat", "malware", "ransomware", "zero-day", "0day"]
HEADERS = {"User-Agent": "c4a-alerts-bot/2.0"}

def is_relevant(text: str) -> bool:
    """Check if the text contains any relevant security keywords."""
    return any(keyword in text.lower() for keyword in KEYWORDS)

def fetch_threat_feeds(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Parse RSS feeds from various threat intelligence sources.
    """
    logging.info("[threatfeeds] Fetching threat intelligence feeds...")
    all_articles = []
    
    # Get current date and date 3 days ago for filtering
    now = datetime.now()
    three_days_ago = now - timedelta(days=3)
    
    for source_name, feed_url in THREAT_FEEDS.items():
        try:
            response = requests.get(feed_url, headers=HEADERS, timeout=15)
            if response.status_code != 200:
                logging.warning(f"⚠️ Failed to fetch {source_name} feed: HTTP {response.status_code}")
                continue
                
            feed = feedparser.parse(response.content)
            
            for entry in feed.entries[:5]:  # Limit to 5 entries per source
                # Try to parse the published date
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])
                
                # Skip entries older than 3 days
                if pub_date and pub_date < three_days_ago:
                    continue
                    
                title = entry.title
                summary = entry.summary if hasattr(entry, 'summary') else ""
                
                # Only include relevant security articles
                if is_relevant(title) or is_relevant(summary):
                    all_articles.append({
                        "title": title,
                        "summary": summary[:200] + "..." if len(summary) > 200 else summary,
                        "url": entry.link,
                        "published": pub_date.isoformat() if pub_date else "Unknown",
                        "source": source_name
                    })
                
                if len(all_articles) >= limit:
                    return all_articles
                    
        except Exception as e:
            logging.error(f"❌ Error fetching {source_name} feed: {e}")
    
    return all_articles
