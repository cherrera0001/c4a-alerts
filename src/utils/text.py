# -*- coding: utf-8 -*-
import re
from html import unescape as html_unescape

_MD2_ESCAPE_RE = re.compile(r'([_\*\[\]\(\)~`>#+\-=|{}.!])')

def escape_markdown(text: str, version: int = 2) -> str:
    if not text:
        return ""
    if version == 2:
        return _MD2_ESCAPE_RE.sub(r'\\\1', text)
    return re.sub(r'([_\*\`\[\]])', r'\\\1', text)

def strip_html(text: str) -> str:
    if not text:
        return ""
    no_tags = re.sub(r'<[^>]+>', '', text)
    return html_unescape(no_tags)

def clean_whitespace(text: str) -> str:
    if not text:
        return ""
    return re.sub(r'\s+', ' ', text).strip()

def truncate(text: str, limit: int, suffix: str = "…") -> str:
    if not text or len(text) <= limit:
        return text or ""
    cut = text[:limit]
    space = cut.rfind(' ')
    if space > max(0, limit - 20):
        cut = cut[:space]
    return cut.rstrip() + suffix
