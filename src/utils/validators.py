# -*- coding: utf-8 -*-
import re
from urllib.parse import urlparse

# Regex laxa para URL HTTP(S)
_URL_RE = re.compile(r'^(https?://)[^\s/$.?#].[^\s]*$', re.IGNORECASE)
# CVE: CVE-2024-1234, cve_2024_01234, "CVE 2024 1234", etc.
_CVE_RE = re.compile(r'(?i)\bCVE[-_\s]?(\d{4})[-_\s]?(\d{4,7})\b')

def validate_url(url: str) -> bool:
    """Valida URLs http/https sencillas (sin espacios, con netloc)."""
    if not url or not isinstance(url, str):
        return False
    u = url.strip()
    if len(u) > 2048 or any(ch.isspace() for ch in u):
        return False
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    # Filtro rápido adicional (opcional)
    if not _URL_RE.match(u):
        return False
    return True

def sanitize_cve_id(value: str) -> str:
    """
    Normaliza un CVE a formato 'CVE-YYYY-NNNN...'.
    Devuelve '' si no se detecta un CVE válido.
    """
    if not value:
        return ""
    m = _CVE_RE.search(value.strip())
    if not m:
        return ""
    year, num = m.group(1), m.group(2).lstrip("0")
    # Rellena a al menos 4 dígitos (CVE-YYYY-0001)
    if len(num) < 4:
        num = num.rjust(4, "0")
    return f"CVE-{year}-{num}"
