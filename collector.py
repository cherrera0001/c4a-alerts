import requests

def get_latest_cves(limit=1):
    url = "https://cve.circl.lu/api/last"
    try:
        cves = requests.get(url, timeout=10).json()
        return [
            f"🚨 *Nuevo CVE:* `{cve.get('id', 'Sin ID')}`\n📝 {cve.get('summary', 'Sin descripción')}"
            for cve in cves[:limit]
        ]
    except Exception as e:
        return [f"⚠️ Error al consultar CVEs: {str(e)}"]


def get_latest_pocs(limit=2):
    url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/latest.json"
    try:
        data = requests.get(url, timeout=10).json()
        alerts = []
        for item in data[:limit]:
            cve = item.get("cve_id", "Sin ID")
            desc = item.get("description", "Sin descripción")
            link = item.get("html_url", "")
            alerts.append(f"🧪 *PoC GitHub*\n🔎 {cve}\n📝 {desc}\n🔗 {link}")
        return alerts
    except Exception as e:
        return [f"⚠️ Error al consultar PoCs: {str(e)}"]
