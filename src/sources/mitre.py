import logging
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any

MITRE_URL = "https://attack.mitre.org/techniques/enterprise/"
HEADERS = {"User-Agent": "c4a-alerts-bot/2.0"}

def fetch_mitre_techniques(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Scrape MITRE ATT&CK techniques and return the most relevant ones.
    """
    logging.info("[mitre] Fetching MITRE ATT&CK techniques...")
    techniques = []
    
    try:
        response = requests.get(MITRE_URL, headers=HEADERS, timeout=15)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        technique_table = soup.select("table.table.techniques-table tbody tr")
        
        for row in technique_table[:limit]:
            cells = row.find_all("td")
            if len(cells) >= 3:
                technique_id = cells[0].text.strip()
                name = cells[1].text.strip()
                tactics = cells[2].text.strip()
                
                link_element = cells[1].find("a")
                link = f"https://attack.mitre.org{link_element['href']}" if link_element else MITRE_URL
                
                techniques.append({
                    "id": technique_id,
                    "name": name,
                    "tactics": tactics,
                    "url": link,
                    "source": "MITRE ATT&CK"
                })
                
        return techniques
        
    except Exception as e:
        logging.error(f"❌ Error fetching MITRE techniques: {e}")
        return []
