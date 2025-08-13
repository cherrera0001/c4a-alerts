# Compatibilidad con imports antiguos de src.utils
# - escape_markdown
# - validate_url, sanitize_cve_id
# - coerce_utc, now_utc, ensure_aware, age_hours

import re
from .validators import validate_url, sanitize_cve_id
from .datetime import parse_any_dt as coerce_utc, now_utc, ensure_aware, age_hours

def escape_markdown(text: str) -> str:
    """Escape básico para Markdown/Telegram."""
    if not text:
        return ""
    special = r'[_*[\]()~`>#+\-=|{}.!]'
    return re.sub(special, lambda m: f"\\{m.group(0)}", text)

__all__ = [
    "escape_markdown",
    "validate_url", "sanitize_cve_id",
    "coerce_utc", "now_utc", "ensure_aware", "age_hours",
]
