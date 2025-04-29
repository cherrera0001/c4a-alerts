import os
import requests

def fetch_github_advisories(limit=10):
    token = os.getenv("GHSA_TOKEN")
    if not token:
        return []

    query = f"""
    {{
      securityAdvisories(first: {limit}, orderBy: {{field: PUBLISHED_AT, direction: DESC}}) {{
        nodes {{
          ghsaId
          summary
          description
          publishedAt
          references {{ url }}
          identifiers {{ type value }}
        }}
      }}
    }}
    """

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            "https://api.github.com/graphql",
            json={"query": query},
            headers=headers,
            timeout=10
        )

        response.raise_for_status()
        data = response.json()
        advisories = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])

        results = []
        for a in advisories:
            results.append({
                "id": a.get("ghsaId"),
                "title": a.get("summary", ""),
                "description": a.get("description", ""),
                "published": a.get("publishedAt"),
                "url": a["references"][0]["url"] if a.get("references") else None,
                "source": "GitHub Security Advisories"
            })

        return results

    except Exception as e:
        print(f"[GitHub Advisories] ❌ Error al obtener datos: {e}")
        return []
