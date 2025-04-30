import json
import csv
from datetime import datetime

with open("alerts_history.json", "r") as f:
    data = json.load(f)

with open("alerts_history.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["id", "title", "published", "source", "url"])
    writer.writeheader()
    for entry in data:
        writer.writerow({
            "id": entry.get("id", ""),
            "title": entry.get("title", ""),
            "published": entry.get("published", ""),
            "source": entry.get("source", ""),
            "url": entry.get("url", "")
        })

print(f"[{datetime.utcnow().isoformat()}] CSV generado con {len(data)} registros.")
