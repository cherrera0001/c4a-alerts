from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, Union

ISO_SEPS = ("T", " ")

def _try_fromisoformat(s: str) -> Optional[datetime]:
    """
    Acepta ISO básicos:
      - YYYY-MM-DD
      - YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]
      - YYYY-MM-DD HH:MM:SS[.fff]
    """
    try:
        s2 = s.strip()
        # Normaliza "Z" → "+00:00" para %z/fromisoformat
        if s2.endswith("Z"):
            s2 = s2[:-1] + "+00:00"

        # Fecha sola
        if not any(sep in s2 for sep in ISO_SEPS) and len(s2) == 10:
            return datetime.fromisoformat(s2)

        return datetime.fromisoformat(s2)
    except Exception:
        return None

def parse_any_dt(value: Union[str, datetime], default_tz=timezone.utc) -> datetime:
    """Parsea datetimes de feeds diversos y retorna *aware UTC* de forma robusta."""
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        dt = _try_fromisoformat(s)

        if dt is None:
            # RFC 2822/Email: "Tue, 13 Aug 2025 02:50:22 +0000" etc.
            for fmt in (
                "%a, %d %b %Y %H:%M:%S %z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
            ):
                try:
                    # Para el caso %z, ya normalizamos "Z" arriba si venía.
                    dt = datetime.strptime(s.replace("Z", "+00:00"), fmt)
                    break
                except Exception:
                    dt = None

        if dt is None:
            # Timestamp entero
            try:
                ts = int(s)
                dt = datetime.fromtimestamp(ts)
            except Exception:
                # Último recurso: ahora (evita crasheo en scoring)
                dt = datetime.now()

    # Fuerza tz y convierte a UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)

def ensure_aware(dt: datetime, default_tz=timezone.utc) -> datetime:
    """Asegura tzinfo y retorna en UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)

def coerce_utc(value: Union[str, datetime]) -> datetime:
    """Atajo para forzar cualquier input a aware-UTC."""
    return parse_any_dt(value)

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def age_hours(dt: Union[str, datetime], now: Optional[datetime] = None) -> float:
    """Horas transcurridas entre dt y ahora (todo en UTC)."""
    base = now or now_utc()
    return (ensure_aware(base) - coerce_utc(dt)).total_seconds() / 3600.0
