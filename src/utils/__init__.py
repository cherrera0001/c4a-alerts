# Compatibilidad con imports antiguos: "from src.utils import escape_markdown"
from .text import escape_markdown, strip_html, clean_whitespace, truncate

__all__ = ["escape_markdown", "strip_html", "clean_whitespace", "truncate"]
