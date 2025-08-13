# src/utils/__init__.py
# Re-exporta utilidades para mantener compatibilidad con: from src.utils import ...

import re
from .validators import validate_url, sanitize_cve_id
from .datetime import parse_any_dt as coerce_utc, now_utc, age_hours

def escape_markdown(text: str) -> str:
    """Escape básico para Markdown/Telegram."""
    if not text:
        return ""
    special = r'[_*[\]()~`>#+\-=|{}.!]'
    return re.sub(special, lambda m: f"\\{m.group(0)}", text)

__all__ = [
    "escape_markdown",
    "validate_url", "sanitize_cve_id",
    "coerce_utc", "now_utc", "age_hours",
]
