# src/sources/anci.py
import os
import json
import math
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

DEFAULT_TIMEOUT = 30
TOKEN_TTL_SECONDS = 55 * 60  # renovamos 5 min antes de expirar (API dice 60 min)

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_dt(raw: Any) -> Optional[datetime]:
    """Acepta '2024-01-10T15:33:06', '2024-01-10T15:33:06Z', o epoch int/str."""
    if raw is None:
        return None
    try:
        # epoch (int o str)
        if isinstance(raw, (int, float)) or (isinstance(raw, str) and raw.isdigit()):
            dt = datetime.fromtimestamp(int(raw), tz=timezone.utc)
            return dt
        s = str(raw).strip()
        if s.endswith("Z"):
            s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _safe_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat() if dt else None

def _make_id(prefix: str, payload: Dict[str, Any]) -> str:
    h = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    return f"anci:{prefix}:{h}"

class _Auth:
    def __init__(self) -> None:
        self.token: Optional[str] = None
        self.expires_at: Optional[datetime] = None

    def valid(self) -> bool:
        return bool(self.token) and self.expires_at and _now_utc() < self.expires_at

class ANCIClient:
    """
    Cliente robusto para API ANCI (MISP CSIRT Nacional).
    Reintenta 401/429 y respeta Retry-After.
    """
    def __init__(self, base_url: str, username: str, password: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        if not base_url.endswith("/"):
            base_url += "/"
        self.base_url = base_url
        self.username = username
        self.password = password
        self.auth = _Auth()
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, http2=True)

    @classmethod
    def from_env(cls) -> "ANCIClient":
        base = os.getenv("ANCI_BASE_URL") or os.getenv("ANCT_BASE_URL")  # por si el secret tiene el typo
        user = os.getenv("ANCI_USERNAME")
        pwd  = os.getenv("ANCI_PASSWORD")
        if not base or not user or not pwd:
            raise RuntimeError("Faltan variables ANCI_BASE_URL/ANCI_USERNAME/ANCI_PASSWORD.")
        return cls(base, user, pwd)

    async def close(self) -> None:
        await self._client.aclose()

    async def _ensure_token(self) -> None:
        if self.auth.valid():
            return
        # login
        r = await self._client.post("token", json={"username": self.username, "password": self.password})
        if r.status_code == 401:
            raise RuntimeError("ANCI: credenciales inválidas (401).")
        r.raise_for_status()
        data = r.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("ANCI: respuesta de token sin 'access_token'.")
        self.auth.token = token
        self.auth.expires_at = _now_utc() + timedelta(seconds=TOKEN_TTL_SECONDS)

    async def _request(self, path: str, payload: Dict[str, Any], *, max_retries: int = 3) -> Dict[str, Any]:
        await self._ensure_token()
        backoff = 1.0
        for attempt in range(max_retries + 1):
            headers = {"Authorization": f"Bearer {self.auth.token}"}
            r = await self._client.post(path, headers=headers, json=payload)
            if r.status_code == 401:
                # token expirado/invalidado → refrescar una vez
                self.auth.token = None
                await self._ensure_token()
                headers = {"Authorization": f"Bearer {self.auth.token}"}
                r = await self._client.post(path, headers=headers, json=payload)
            if r.status_code == 429:
                retry_after = r.headers.get("Retry-After")
                sleep_s = float(retry_after) if retry_after and retry_after.isdigit() else backoff
                await asyncio.sleep(sleep_s)
                backoff = min(backoff * 2, 30)
                continue
            try:
                r.raise_for_status()
                return r.json()
            except httpx.HTTPStatusError as e:
                if attempt < max_retries:
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30)
                    continue
                raise RuntimeError(f"ANCI {path} error {r.status_code}: {e}") from e
        raise RuntimeError(f"ANCI {path}: agotados los reintentos")

    async def fetch_ioc_ips(self, fdesde: datetime, fhasta: datetime, amenaza: Optional[Any]=None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"fecha_desde": _safe_iso(fdesde), "fecha_hasta": _safe_iso(fhasta)}
        if amenaza is not None:
            body["amenaza"] = amenaza
        return await self._request("ioc/ip_amenazas", body)

    async def fetch_domains(self, fdesde: datetime, fhasta: datetime, dominio: Optional[Any]=None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"fecha_desde": _safe_iso(fdesde), "fecha_hasta": _safe_iso(fhasta)}
        if dominio is not None:
            body["dominio"] = dominio
        return await self._request("ioc/dominios", body)

    async def fetch_hashes(self, fdesde: datetime, fhasta: datetime, amenaza: Optional[Any]=None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"fecha_desde": _safe_iso(fdesde), "fecha_hasta": _safe_iso(fhasta)}
        if amenaza is not None:
            body["amenaza"] = amenaza
        return await self._request("ioc/hashes", body)

    async def fetch_urls(self, fdesde: datetime, fhasta: datetime) -> Dict[str, Any]:
        return await self._request("ioc/urls", {"fecha_desde": _safe_iso(fdesde), "fecha_hasta": _safe_iso(fhasta)})

    async def fetch_phishing_emails(self, fdesde: datetime, fhasta: datetime, correo: Optional[Any]=None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"fecha_desde": _safe_iso(fdesde), "fecha_hasta": _safe_iso(fhasta)}
        if correo is not None:
            body["correo"] = correo
        return await self._request("ioc/correos_phishing", body)

# ---------- Normalización a "raw alert" para tu pipeline ----------

def _mk_ioc_item(v: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": v.get("tipo") or v.get("type"),
        "value": v.get("valor") or v.get("value"),
        "first_seen": _safe_iso(_parse_dt(v.get("fecha_creacion"))),
    }

def _alert_from_threat(bucket_name: str, items: List[Dict[str, Any]], kind: str, base_url: str) -> Dict[str, Any]:
    iocs = [_mk_ioc_item(x) for x in items if x]
    payload = {"threat": bucket_name, "kind": kind, "count": len(iocs)}
    return {
        "id": _make_id(f"{kind}:{bucket_name}", payload),
        "title": f"ANCI/MISP – {kind.upper()} para '{bucket_name}' ({len(iocs)} IoC)",
        "description": f"Conjunto de IoC entregados por ANCI/MISP ({kind}) para '{bucket_name}'.",
        "source": "ANCI MISP",
        "url": base_url,  # documentación/base
        "published": _safe_iso(max((_parse_dt(x.get("fecha_creacion")) for x in items if x.get("fecha_creacion")), default=_now_utc())),
        "iocs": iocs,
        "tags": ["ANCI", "MISP", kind],
    }

def _alert_from_flat(items: List[Dict[str, Any]], kind: str, base_url: str) -> Dict[str, Any]:
    iocs = [_mk_ioc_item(x) for x in items if x]
    payload = {"kind": kind, "count": len(iocs)}
    return {
        "id": _make_id(f"{kind}:flat", payload),
        "title": f"ANCI/MISP – {kind.upper()} ({len(iocs)} IoC)",
        "description": f"IoC de tipo {kind} entregados por ANCI/MISP.",
        "source": "ANCI MISP",
        "url": base_url,
        "published": _safe_iso(max((_parse_dt(x.get("fecha_creacion")) for x in items if x.get("fecha_creacion")), default=_now_utc())),
        "iocs": iocs,
        "tags": ["ANCI", "MISP", kind],
    }

async def fetch_anci_iocs(limit: int = 15, days: int = 7) -> List[Dict[str, Any]]:
    """
    Función de fuente para tu SourceManager (async). Une IP/domains/hashes/urls y correos.
    Devuelve una lista de dicts (raw alerts) compatible con tu processor.
    """
    client = ANCIClient.from_env()
    try:
        fhasta = _now_utc()
        fdesde = fhasta - timedelta(days=days)

        # Ejecutamos en paralelo
        results = await asyncio.gather(
            client.fetch_ioc_ips(fdesde, fhasta),         # agrupado por amenazas
            client.fetch_domains(fdesde, fhasta, dominio=None),  # lista plana
            client.fetch_hashes(fdesde, fhasta),         # agrupado por amenazas
            client.fetch_urls(fdesde, fhasta),           # lista plana
            client.fetch_phishing_emails(fdesde, fhasta, correo=None),  # agrupado por correo
            return_exceptions=True,
        )

        alerts: List[Dict[str, Any]] = []
        base_url = client.base_url.rstrip("/")

        # 1) IPs por amenaza (dict: amenazas -> list[IoCItem])
        ip_data = results[0]
        if isinstance(ip_data, dict):
            amenazas = (ip_data.get("response") or {}).get("amenazas") or {}
            for name, items in amenazas.items():
                alerts.append(_alert_from_threat(name, items or [], "ips", base_url))

        # 2) dominios (lista)
        dom_data = results[1]
        if isinstance(dom_data, dict):
            dominios = (dom_data.get("response") or {}).get("dominios") or []
            alerts.append(_alert_from_flat(dominios, "dominios", base_url))

        # 3) hashes por amenaza (dict)
        h_data = results[2]
        if isinstance(h_data, dict):
            amenazas = (h_data.get("response") or {}).get("amenazas") or {}
            for name, items in amenazas.items():
                alerts.append(_alert_from_threat(name, items or [], "hashes", base_url))

        # 4) urls (lista)
        url_data = results[3]
        if isinstance(url_data, dict):
            urls = (url_data.get("response") or {}).get("urls") or []
            alerts.append(_alert_from_flat(urls, "urls", base_url))

        # 5) correos phishing (dict correos -> {fecha, ioc_correo})
        mail_data = results[4]
        if isinstance(mail_data, dict):
            correos = (mail_data.get("response") or {}).get("correos") or {}
            for correo, obj in correos.items():
                items = obj.get("ioc_correo", []) if isinstance(obj, dict) else []
                alerts.append(_alert_from_threat(correo, items, "phishing", base_url))

        # limitar
        return alerts[:max(0, limit)]
    finally:
        await client.close()
