import requests

def get_latest_cves(limit=1):
    url = "https://cve.circl.lu/api/last"
    try:
        cves = requests.get(url, timeout=10).json()
        return [
            f"*Nuevo CVE:* {cve['id']}\n📝 {cve['summary']}"
            for cve in cves[:limit]
        ]
    except Exception as e:
        return [f"⚠️ Error al consultar CVEs: {str(e)}"]
