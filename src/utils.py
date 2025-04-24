import re
import requests


def escape_markdown(text: str) -> str:
    """
    Escapa caracteres especiales según las reglas de MarkdownV2 de Telegram.
    """
    escape_chars = r"_*[]()~`>#+-=|{}.!"
    return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", text)


def validate_url(url: str) -> bool:
    """
    Verifica si un URL es accesible y devuelve HTTP 200.
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException:
        return False


def sanitize_cve_id(cve_id: str) -> str:
    """
    Valida y sanitiza un CVE ID según el formato CVE-YYYY-NNNNN.
    """
    pattern = r"^CVE-\d{4}-\d{4,7}$"
    return cve_id if re.match(pattern, cve_id) else "INVALID_CVE"
