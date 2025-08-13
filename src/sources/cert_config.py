# src/sources/cert_config.py
"""
Configuración centralizada de feeds CERT y verificación de salud.
Un único lugar para mantener las URLs y su estado.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime
import logging

@dataclass
class CertFeedConfig:
    """Configuración de un feed CERT"""
    name: str
    url: str
    enabled: bool = True
    last_check: Optional[datetime] = None
    last_status: Optional[int] = None
    last_error: Optional[str] = None
    timeout: int = 15
    
    @property
    def is_healthy(self) -> bool:
        """Feed considerado saludable si último status fue 200"""
        return self.last_status == 200 if self.last_status else False


# Configuración ÚNICA de feeds CERT
CERT_FEEDS_CONFIG: Dict[str, CertFeedConfig] = {
    # Feeds funcionales
    "CISA-US": CertFeedConfig(
        name="CISA-US",
        url="https://www.cisa.gov/uscert/ncas/alerts.xml",
        enabled=True
    ),
    "CERT-FR": CertFeedConfig(
        name="CERT-FR", 
        url="https://www.cert.ssi.gouv.fr/feed/",
        enabled=True
    ),
    "JPCERT-JP": CertFeedConfig(
        name="JPCERT-JP",
        url="https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
        enabled=True
    ),
    "NCSC-UK": CertFeedConfig(
        name="NCSC-UK",
        url="https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        enabled=True
    ),
    
    # Feeds con problemas conocidos (deshabilitados por defecto)
    "CERT-BR": CertFeedConfig(
        name="CERT-BR",
        url="https://www.cert.br/rss/feed/alertas/",
        enabled=False,  # 404 persistente
        last_error="404 Not Found"
    ),
    "CERT-EU": CertFeedConfig(
        name="CERT-EU",
        url="https://cert.europa.eu/static/SecurityAdvisories/CERT-EU_SA.xml",
        enabled=False,  # URL cambió
        last_error="404 Not Found - Verificar nueva URL"
    ),
    "CERT-MX": CertFeedConfig(
        name="CERT-MX",
        url="https://www.gob.mx/certmx/rss",
        enabled=False,  # Sitio reorganizado
        last_error="404 Not Found - Sitio reorganizado"
    ),
    "ICS-CERT": CertFeedConfig(
        name="ICS-CERT",
        url="https://www.cisa.gov/uscert/ics/alerts.xml",
        enabled=False,  # URL obsoleta
        last_error="404 Not Found - Migrado a CISA principal"
    ),
}

def get_active_feeds() -> Dict[str, str]:
    """Retorna solo los feeds activos como dict simple para backward compatibility"""
    return {
        name: config.url 
        for name, config in CERT_FEEDS_CONFIG.items() 
        if config.enabled
    }

def get_all_feeds() -> Dict[str, str]:
    """Retorna todos los feeds (para verificación de salud)"""
    return {
        name: config.url 
        for name, config in CERT_FEEDS_CONFIG.items()
    }

def update_feed_status(name: str, status: int, error: Optional[str] = None) -> None:
    """Actualiza el estado de un feed después de verificación"""
    if name in CERT_FEEDS_CONFIG:
        config = CERT_FEEDS_CONFIG[name]
        config.last_check = datetime.now()
        config.last_status = status
        config.last_error = error
        
        # Auto-deshabilitar si hay errores persistentes
        if status != 200:
            logging.warning(f"Feed {name} retornó status {status}")
            # Podríamos implementar lógica para deshabilitar después de N fallos

def get_health_report() -> Dict:
    """Genera reporte de salud de todos los feeds"""
    total = len(CERT_FEEDS_CONFIG)
    enabled = sum(1 for c in CERT_FEEDS_CONFIG.values() if c.enabled)
    healthy = sum(1 for c in CERT_FEEDS_CONFIG.values() if c.is_healthy)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "total_feeds": total,
        "enabled_feeds": enabled,
        "healthy_feeds": healthy,
        "feeds": {
            name: {
                "url": config.url,
                "enabled": config.enabled,
                "healthy": config.is_healthy,
                "last_check": config.last_check.isoformat() if config.last_check else None,
                "last_status": config.last_status,
                "last_error": config.last_error
            }
            for name, config in CERT_FEEDS_CONFIG.items()
        }
    }