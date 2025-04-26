# src/threatfeeds.py

import logging
import requests
import feedparser
from typing import List, Dict, Any
from datetime import datetime, timedelta

# RSS feeds from trusted cybersecurity sources
THREAT_FEEDS = {
    "ThreatPost": "https://threatpost.com/feed/",
    "HackerNews": "https://thehackernews.com/feeds/posts/default",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    "DarkReading": "https://www.darkreading.com/rss.xml"
}

# Expanded critical keywords
CRITICAL_KEYWORDS = [
    "vulnerability", "exploit", "cve", "attack", "threat",
    "malware", "ransomware", "zero-day", "0day", "bypass",
    "escalation", "authentication bypass", "privilege escalation",
    "remote code execution", "rce", "exfiltration", "zero day"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/91.0.4472.124 Safari/537.36 c4a-alerts-bot/2.0"
}

def is_relevant(text: str) -> bool:
    """Check if the text contains any relevant security keywords."""
    text = text.lower()
    return any(keyword in text for keyword in CRITICAL_KEYWORDS)

def fetch_threat_feeds(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch and parse RSS feeds from trusted cybersecurity sources.
    Filters entries by relevance and freshness (last 3 days).
    """
    logging.info("[threatfeeds] Fetching threat intelligence feeds...")
    all_alerts = []

    now = datetime.utcnow()
    three_days_ago = now - timedelta(days=3)

    for source_name, feed_url in THREAT_FEEDS.items():
        try:
            response = requests.get(feed_url, headers=HEADERS, timeout=15)
            response.raise_for_status()
            feed = feedparser.parse(response.content)

            for entry in feed.entries:
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])

                if pub_date and pub_date < three_days_ago:
                    continue

                title = entry.title
                summary = getattr(entry, 'summary', "")
                tags = [tag.term.lower() for tag in getattr(entry, 'tags', [])]

                if is_relevant(title) or is_relevant(summary) or any(is_relevant(tag) for tag in tags):
                    all_alerts.append({
                        "title": title,
                        "summary": (summary[:200] + "...") if len(summary) > 200 else summary,
                        "url": entry.link,
                        "published": pub_date.isoformat() if pub_date else "Unknown",
                        "source": source_name
                    })

                if len(all_alerts) >= limit:
                    logging.info(f"[threatfeeds] Reached limit of {limit} alerts.")
                    return all_alerts

        except Exception as e:
            logging.error(f"❌ Error fetching {source_name} feed: {e}")

    return all_alerts
