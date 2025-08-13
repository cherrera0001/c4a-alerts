# FILE: src/models.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, HttpUrl, Field
import hashlib
from .utils.datetime import parse_any_dt

class Alert(BaseModel):
    id: str = Field(..., description="Hash estable del evento")
    source: str
    title: str
    description: str
    url: Optional[HttpUrl] = None
    published: datetime
    cve_ids: List[str] = []
    vendor: Optional[str] = None
    product: Optional[str] = None
    cvss: Optional[float] = None
    has_poc: bool = False
    tags: List[str] = []

    @staticmethod
    def make_id(source: str, title: str, url: str, published: object) -> str:
        p = parse_any_dt(published).date().isoformat()
        base = f"{(source or '').lower()}|{(title or '').lower()}|{(url or '').lower()}|{p}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    @staticmethod
    def coerce_dt(value: object) -> datetime:
        return parse_any_dt(value)

@dataclass
class PipelineResult:
    success: bool
    alerts_collected: int
    alerts_processed: int
    alerts_sent: int
    critical_alerts_count: int
    execution_time_seconds: float
    errors: List[str]
