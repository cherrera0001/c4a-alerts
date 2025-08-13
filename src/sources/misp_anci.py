# FILE: src/sources/misp_anci.py
from __future__ import annotations
import os
import time
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib

logger = logging.getLogger(__name__)

# ---- Helpers de fecha/parse ----
FMT = "%Y-%m-%d %H:%M:%S"

def _fmt(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(FMT)

def _parse_fecha(valor: Any) -> Optional[str]:
    """Normaliza fechas a ISO corta (YYYY-MM-DDTHH:MM:SSZ) para consistencia visual."""
    if valor is None:
        return None
    try:
        # string con fecha
        if isinstance(valor, str):
            # admite "2024-01-10T15:33:06" o "2024-01-01 00:00:00"
            v = valor.replace("Z", "").replace("T", " ")
            dt = datetime.fromisoformat(v)
            return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        # epoch numérico (algunos ejemplos muestran timestamps)
        if isinstance(valor, (int, float)):
            dt = datetime.fromtimestamp(float(valor), tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        pass
    return None

def _mk_id(prefix: str, *parts: str) -> str:
    raw = "||".join([prefix, *[p or "" for p in parts]])
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{h}"

# ---- Cliente simple con cache de token ----
class ANCIClient:
    def __init__(self,
                 base_url: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 timeout: int = 30):
        self.base_url = (base_url or os.getenv("ANCI_BASE_URL", "")).rstrip("/")
        self.username = username or os.getenv("ANCI_USERNAME", "")
        self.password = password or os.getenv("ANCI_PASSWORD", "")
        self.timeout = timeout

        if not (self.base_url and self.username and self.password):
            raise RuntimeError("ANCI_BASE_URL/ANCI_USERNAME/ANCI_PASSWORD requeridos")

        # requests Session con reintentos (para 5xx/transitorios)
        self.s = requests.Session()
        retry = Retry(
            total=3,
            read=3,
            connect=3,
            status=3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["POST"]),
            backoff_factor=1.0,
        )
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        self.s.mount("http://", HTTPAdapter(max_retries=retry))

        self._token: Optional[str] = None
        self._token_exp: float = 0.0  # epoch seconds

    def _auth(self) -> None:
        url = f"{self.base_url}/token"
        resp = self.s.post(url, json={"username": self.username, "password": self.password}, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"ANCI auth fallo: {resp.status_code} {resp.text}")
        data = resp.json()
        tok = data.get("access_token")
        ttype = data.get("token_type", "bearer")
        if not tok:
            raise RuntimeError("ANCI auth sin access_token")
        self._token = f"{ttype} {tok}"
        # dura 60 min según spec → cachea por 55 min de seguridad
        self._token_exp = time.time() + 55 * 60
        logger.info("🔐 ANCI token obtenido")

    def _ensure_token(self):
        if not self._token or time.time() >= self._token_exp:
            self._auth()

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_token()
        url = f"{self.base_url}{path}"
        headers = {"Authorization": self._token}
        resp = self.s.post(url, json=payload, headers=headers, timeout=self.timeout)

        # 401 → refrescar token una vez
        if resp.status_code == 401:
            logger.info("🔄 ANCI 401: refrescando token")
            self._auth()
            headers = {"Authorization": self._token}
            resp = self.s.post(url, json=payload, headers=headers, timeout=self.timeout)

        # 429 → respetar Retry-After si viene, si no backoff fijo
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After")
            wait = float(ra) if ra else 5.0
            logger.warning(f"⏳ ANCI 429 Too Many Requests, esperando {wait}s")
            time.sleep(wait)
            resp = self.s.post(url, json=payload, headers=headers, timeout=self.timeout)

        if resp.status_code >= 400:
            raise RuntimeError(f"ANCI {path} fallo: {resp.status_code} {resp.text}")

        try:
            return resp.json()
        except Exception as e:
            raise RuntimeError(f"ANCI {path} JSON inválido: {e}")

# ---- Normalización de IoCs a 'alertas' (diccionarios) ----
def _mk_alert(source: str,
              ioc_tipo: str,
              ioc_valor: str,
              created: Optional[str],
              threat: Optional[str],
              extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    title = f"{ioc_tipo}: {ioc_valor}"
    desc = f"IoC {ioc_tipo} observado"
    if threat:
        desc += f" asociado a amenaza '{threat}'"
    if created:
        desc += f" (fecha: {created})"
    alert = {
        "id": _mk_id("ANCI", ioc_tipo, ioc_valor, created or ""),
        "title": title,
        "description": desc,
        "source": source,
        "ioc_type": ioc_tipo,
        "ioc_value": ioc_valor,
        "observed_at": created,
        "threat": threat,
        "url": None,  # la API no expone enlace público por IoC
    }
    if extra:
        alert.update(extra)
    return alert

def _window_payload(since_dt: Optional[datetime], until_dt: Optional[datetime]) -> Dict[str, str]:
    now = datetime.now(timezone.utc) if until_dt is None else until_dt
    desde = since_dt or (now - timedelta(hours=24))
    return {"fecha_desde": _fmt(desde), "fecha_hasta": _fmt(now)}

# ---- Función principal (sync) que reúne todos los IoC ----
def fetch_anci_iocs(since_dt: Optional[datetime] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Descarga IoCs (IPs, dominios, URLs, hashes, archivos) del MISP ANCI,
    normaliza a 'alertas' y devuelve una lista (máx 'limit').
    """
    client = ANCIClient()
    payload = _window_payload(since_dt, None)

    alerts: List[Dict[str, Any]] = []

    # 1) IPs por amenaza
    try:
        data = client._post("/ioc/ip_amenazas", payload)
        amenazas = data.get("response", {}).get("amenazas") or {}
        for threat, items in amenazas.items():
            for it in items or []:
                tipo = it.get("tipo") or "ip"
                valor = it.get("valor") or ""
                fc = _parse_fecha(it.get("fecha_creacion"))
                if valor:
                    alerts.append(_mk_alert("ANCI MISP", tipo, valor, fc, threat))
    except Exception as e:
        logger.warning(f"ANCI ip_amenazas error: {e}")

    # 2) Dominios
    try:
        data = client._post("/ioc/dominios", payload)
        doms = data.get("response", {}).get("dominios") or []
        for it in doms:
            tipo = it.get("tipo") or "domain"
            valor = it.get("valor") or ""
            fc = _parse_fecha(it.get("fecha_creacion"))
            if valor:
                alerts.append(_mk_alert("ANCI MISP", tipo, valor, fc, None))
    except Exception as e:
        logger.warning(f"ANCI dominios error: {e}")

    # 3) URLs
    try:
        data = client._post("/ioc/urls", payload)
        urls = data.get("response", {}).get("urls") or []
        for it in urls:
            # hay ejemplos con 'fecha_creaacion_timestamp' mal escrito → tolerar
            fc = _parse_fecha(it.get("fecha_creacion") or it.get("fecha_creaacion_timestamp"))
            valor = it.get("valor") or ""
            tipo = it.get("tipo") or "url"
            if valor:
                alerts.append(_mk_alert("ANCI MISP", tipo, valor, fc, None))
    except Exception as e:
        logger.warning(f"ANCI urls error: {e}")

    # 4) Hashes por amenaza
    try:
        data = client._post("/ioc/hashes", payload)
        amenazas = data.get("response", {}).get("amenazas") or {}
        for threat, items in amenazas.items():
            for it in items or []:
                tipo = it.get("tipo") or "hash"
                valor = it.get("valor") or ""
                fc = _parse_fecha(it.get("fecha_creacion"))
                if valor:
                    alerts.append(_mk_alert("ANCI MISP", tipo, valor, fc, threat))
    except Exception as e:
        logger.warning(f"ANCI hashes error: {e}")

    # 5) Archivos (filename + hashes)
    try:
        data = client._post("/ioc/archivos", payload)
        amenazas = data.get("response", {}).get("amenazas") or {}
        for threat, items in amenazas.items():
            for it in items or []:
                fc = _parse_fecha(it.get("fecha_creacion"))
                fname = it.get("filename") or ""
                if fname:
                    alerts.append(_mk_alert("ANCI MISP", "filename", fname, fc, threat))
                for h in it.get("hashes") or []:
                    tipo = h.get("tipo") or "hash"
                    valor = h.get("valor") or ""
                    if valor:
                        alerts.append(_mk_alert("ANCI MISP", tipo, valor, fc, threat, extra={"filename": fname or None}))
    except Exception as e:
        logger.warning(f"ANCI archivos error: {e}")

    # Orden por fecha desc si la tenemos, y recortar a limit
    def _key(a: Dict[str, Any]):
        fc = a.get("observed_at")
        try:
            return datetime.fromisoformat(fc.replace("Z", "+00:00")) if fc else datetime.min.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    alerts.sort(key=_key, reverse=True)
    if limit and limit > 0:
        alerts = alerts[:limit]
    return alerts
