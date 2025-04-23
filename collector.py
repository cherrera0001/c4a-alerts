import requests

def get_latest_cves(limit=1):
    url = "https://cve.circl.lu/api/last"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        cves = response.json()

        alerts = []
        for cve in cves[:limit]:
            cve_id = cve.get("id", "Sin ID")
            summary = cve.get("summary", "Sin descripción")
            alerts.append(f"🚨 *Nuevo CVE:* `{cve_id}`\n📝 {summary}")

        return alerts

    except Exception as e:
        return [f"⚠️ Error al consultar CVEs: {str(e)}"]
