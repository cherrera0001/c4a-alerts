# FILE: src/utils/datetime.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, Union

ISO_SEPS = ("T", " ")

def _try_fromisoformat(s: str) -> Optional[datetime]:
    # Acepta "YYYY-MM-DDTHH:MM:SS" o "YYYY-MM-DD HH:MM:SS" con/sin zona.
    try:
        # Normaliza "Z" → "+00:00"
        s2 = s.strip().replace("Z", "+00:00")
        # Si no hay separador típico, prueba tal cual
        if not any(sep in s2 for sep in ISO_SEPS) and len(s2) == 10:
            # Formato YYYY-MM-DD
            dt = datetime.fromisoformat(s2)
            return dt
        return datetime.fromisoformat(s2)
    except Exception:
        return None

def parse_any_dt(value: Union[str, datetime], default_tz=timezone.utc) -> datetime:
    """Parsea datetimes de feeds diversos. Todo sale como aware-UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        # Intento rápido con fromisoformat tolerante
        dt = _try_fromisoformat(s)
        if dt is None:
            # Fallback extra: timestamps enteros
            try:
                ts = int(s)
                dt = datetime.fromtimestamp(ts)
            except Exception:
                dt = datetime.now()
    # Forzamos tzinfo
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    # Convertimos a UTC
    return dt.astimezone(timezone.utc)

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def age_hours(dt: datetime, now: Optional[datetime] = None) -> float:
    """Horas transcurridas entre 'dt' y 'now' (UTC aware siempre)."""
    now = now or now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (now - dt.astimezone(timezone.utc)).total_seconds() / 3600.0
