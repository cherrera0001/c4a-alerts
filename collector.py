import requests

def get_latest_cves(limit=1):
    url = "https://cve.circl.lu/api/last"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        cves = response.json()

        if not isinstance(cves, list):
            return ["\u26A0\uFE0F Respuesta inesperada de CIRCL: {cves}"]

        alerts = []
        for cve in cves[:limit]:
            cve_id = cve.get("cveMetadata", {}).get("cveId", "Sin ID")
            description = (
                cve.get("containers", {})
                .get("cna", {})
                .get("descriptions", [{}])[0]
                .get("value", "Sin descripción")
            )
            alerts.append(f"\U0001F6A8 *Nuevo CVE:* `{cve_id}`\n\U0001F4DD {description}")

        return alerts

    except Exception as e:
        return [f"\u26A0\uFE0F Error al consultar CVEs: {str(e)}"]


def get_latest_pocs(limit=2):
    url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/gh-pages/latest.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()
        if not isinstance(data, list):
            print("\u26A0\uFE0F Formato inesperado en PoCs JSON.")
            return []

        return [
            f"\U0001F9EA *PoC GitHub*\n\U0001F50E {item.get('cve_id', 'Sin ID')}\n\U0001F4DD {item.get('description', 'Sin descripción')}\n\U0001F517 {item.get('html_url', '')}"
            for item in data[:limit]
        ]

    except Exception as e:
        print(f"\u26A0\uFE0F Error al consultar PoCs desde GitHub: {e}")
        return []
