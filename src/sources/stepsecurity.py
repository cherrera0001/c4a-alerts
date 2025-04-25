import logging
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from datetime import datetime

STEPSECURITY_BLOG_URL = "https://stepsecurity.io/blog"
HEADERS = {"User-Agent": "c4a-alerts-bot/2.0"}

def fetch_stepsecurity_posts(limit: int = 3) -> List[Dict[str, Any]]:
    """
    Parse StepSecurity blog posts.
    """
    logging.info("[stepsecurity] Fetching StepSecurity blog posts...")
    posts = []
    
    try:
        response = requests.get(STEPSECURITY_BLOG_URL, headers=HEADERS, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        blog_posts = soup.select("div.blog-post")
        
        for post in blog_posts[:limit]:
            title_element = post.select_one("h2.blog-post-title")
            date_element = post.select_one("p.blog-post-meta")
            link_element = title_element.find("a") if title_element else None
            
            if title_element and link_element:
                title = title_element.text.strip()
                link = link_element["href"]
                if not link.startswith("http"):
                    link = f"https://stepsecurity.io{link}"
                
                date_str = date_element.text.strip() if date_element else ""
                
                posts.append({
                    "title": title,
                    "url": link,
                    "date": date_str,
                    "source": "StepSecurity"
                })
        
        return posts
        
    except Exception as e:
        logging.error(f"❌ Error fetching StepSecurity blog posts: {e}")
        return []
