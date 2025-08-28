"""
MISP CSIRT Collector
Integración con la API MISP del CSIRT Nacional de Chile
"""

import os
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MISPCsirtCollector:
    """Collector para la API MISP del CSIRT Nacional de Chile"""

    def __init__(self):
        self.base_url = os.getenv('ANCI_BASE_URL', 'https://apimisp.csirt.gob.cl')
        self.username = os.getenv('ANCI_USERNAME', 'crherrera@c4a.cl')
        self.password = os.getenv('ANCI_PASSWORD', '')
        self.token = None
        self.token_expiry = None

    def _get_auth_token(self) -> Optional[str]:
        """Obtener token de autenticación JWT"""
        try:
            if self.token and self.token_expiry and datetime.now() < self.token_expiry:
                return self.token

            auth_url = f"{self.base_url}/token"
            auth_data = {
                "username": self.username,
                "password": self.password
            }

            response = requests.post(auth_url, json=auth_data, timeout=30)
            response.raise_for_status()

            token_data = response.json()
            self.token = token_data.get('access_token')
            # Token válido por 60 minutos
            self.token_expiry = datetime.now() + timedelta(minutes=55)

            logger.info("Token MISP CSIRT obtenido exitosamente")
            return self.token

        except Exception as e:
            logger.error(f"Error obteniendo token MISP CSIRT: {e}")
            return None

    def _make_authenticated_request(self, endpoint: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Realizar petición autenticada a la API MISP"""
        try:
            token = self._get_auth_token()
            if not token:
                return None

            url = f"{self.base_url}{endpoint}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            response = requests.post(url, json=data, headers=headers, timeout=30)
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.error(f"Error en petición MISP CSIRT {endpoint}: {e}")
            return None

    def collect_ip_threats(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Recolectar IPs asociadas a amenazas"""
        try:
            fecha_hasta = datetime.now()
            fecha_desde = fecha_hasta - timedelta(days=days_back)

            data = {
                "fecha_desde": fecha_desde.strftime("%Y-%m-%d %H:%M:%S"),
                "fecha_hasta": fecha_hasta.strftime("%Y-%m-%d %H:%M:%S")
            }

            result = self._make_authenticated_request("/ioc/ip_amenazas", data)
            if not result:
                return []

            alerts = []
            response_data = result.get('response', {})
            amenazas = response_data.get('amenazas', {})

            for amenaza, iocs in amenazas.items():
                for ioc in iocs:
                    alert = {
                        'uid': f"misp_csirt_ip_{amenaza}_{ioc.get('valor', 'unknown')}",
                        'source': 'misp_csirt',
                        'title': f'IP Maliciosa Detectada - {amenaza}',
                        'description': f'IP {ioc.get("valor")} asociada a la amenaza {amenaza}',
                        'severity': 'high',
                        'tags': ['misp_csirt', 'ip', 'threat', amenaza.lower()],
                        'iocs': [{
                            'type': 'ip',
                            'value': ioc.get('valor'),
                            'source': 'misp_csirt'
                        }],
                        'threat_actor': amenaza,
                        'confidence': 0.9,
                        'references': [f"{self.base_url}/docs"],
                        'published_at': ioc.get('fecha_creacion', datetime.now().isoformat()),
                        'raw_data': ioc
                    }
                    alerts.append(alert)

            logger.info(f"Recolectadas {len(alerts)} alertas de IPs desde MISP CSIRT")
            return alerts

        except Exception as e:
            logger.error(f"Error recolectando IPs desde MISP CSIRT: {e}")
            return []

    def collect_suspicious_domains(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Recolectar dominios sospechosos"""
        try:
            fecha_hasta = datetime.now()
            fecha_desde = fecha_hasta - timedelta(days=days_back)

            data = {
                "fecha_desde": fecha_desde.strftime("%Y-%m-%d %H:%M:%S"),
                "fecha_hasta": fecha_hasta.strftime("%Y-%m-%d %H:%M:%S")
            }

            result = self._make_authenticated_request("/ioc/dominios", data)
            if not result:
                return []

            alerts = []
            response_data = result.get('response', {})
            dominios = response_data.get('dominios', [])

            for dominio in dominios:
                alert = {
                    'uid': f"misp_csirt_domain_{dominio.get('valor', 'unknown')}",
                    'source': 'misp_csirt',
                    'title': f'Dominio Sospechoso Detectado',
                    'description': f'Dominio {dominio.get("valor")} identificado como sospechoso',
                    'severity': 'medium',
                    'tags': ['misp_csirt', 'domain', 'suspicious'],
                    'iocs': [{
                        'type': 'domain',
                        'value': dominio.get('valor'),
                        'source': 'misp_csirt'
                    }],
                    'confidence': 0.8,
                    'references': [f"{self.base_url}/docs"],
                    'published_at': dominio.get('fecha_creacion', datetime.now().isoformat()),
                    'raw_data': dominio
                }
                alerts.append(alert)

            logger.info(f"Recolectados {len(alerts)} dominios sospechosos desde MISP CSIRT")
            return alerts

        except Exception as e:
            logger.error(f"Error recolectando dominios desde MISP CSIRT: {e}")
            return []

    def collect_malicious_urls(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Recolectar URLs maliciosas"""
        try:
            fecha_hasta = datetime.now()
            fecha_desde = fecha_hasta - timedelta(days=days_back)

            data = {
                "fecha_desde": fecha_desde.strftime("%Y-%m-%d %H:%M:%S"),
                "fecha_hasta": fecha_hasta.strftime("%Y-%m-%d %H:%M:%S")
            }

            result = self._make_authenticated_request("/ioc/urls", data)
            if not result:
                return []

            alerts = []
            response_data = result.get('response', {})
            urls = response_data.get('urls', [])

            for url in urls:
                alert = {
                    'uid': f"misp_csirt_url_{hash(url.get('valor', ''))}",
                    'source': 'misp_csirt',
                    'title': f'URL Maliciosa Detectada',
                    'description': f'URL {url.get("valor")} identificada como maliciosa',
                    'severity': 'high',
                    'tags': ['misp_csirt', 'url', 'malicious'],
                    'iocs': [{
                        'type': 'url',
                        'value': url.get('valor'),
                        'source': 'misp_csirt'
                    }],
                    'confidence': 0.85,
                    'references': [f"{self.base_url}/docs"],
                    'published_at': url.get('fecha_creacion', datetime.now().isoformat()),
                    'raw_data': url
                }
                alerts.append(alert)

            logger.info(f"Recolectadas {len(alerts)} URLs maliciosas desde MISP CSIRT")
            return alerts

        except Exception as e:
            logger.error(f"Error recolectando URLs desde MISP CSIRT: {e}")
            return []

    def collect_apts(self) -> List[Dict[str, Any]]:
        """Recolectar información de APTs"""
        try:
            data = {
                "fecha_desde": (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S"),
                "fecha_hasta": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            result = self._make_authenticated_request("/apt/categorias", data)
            if not result:
                return []

            alerts = []
            response_data = result.get('response', [])

            for apt in response_data:
                alert = {
                    'uid': f"misp_csirt_apt_{apt.get('nombre_grupo', 'unknown')}",
                    'source': 'misp_csirt',
                    'title': f'APT Detectado - {apt.get("nombre_grupo")}',
                    'description': apt.get('descripcion', 'APT identificado por CSIRT Nacional'),
                    'severity': 'critical',
                    'tags': ['misp_csirt', 'apt', 'threat_actor'],
                    'threat_actor': apt.get('nombre_grupo'),
                    'confidence': 0.95,
                    'references': [f"{self.base_url}/docs"],
                    'published_at': datetime.now().isoformat(),
                    'raw_data': apt
                }
                alerts.append(alert)

            logger.info(f"Recolectados {len(alerts)} APTs desde MISP CSIRT")
            return alerts

        except Exception as e:
            logger.error(f"Error recolectando APTs desde MISP CSIRT: {e}")
            return []

    def collect_all(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Recolectar todas las fuentes de datos de MISP CSIRT"""
        all_alerts = []

        # Recolectar IPs amenazas
        all_alerts.extend(self.collect_ip_threats(days_back))

        # Recolectar dominios sospechosos
        all_alerts.extend(self.collect_suspicious_domains(days_back))

        # Recolectar URLs maliciosas
        all_alerts.extend(self.collect_malicious_urls(days_back))

        # Recolectar APTs
        all_alerts.extend(self.collect_apts())

        logger.info(f"Total recolectado desde MISP CSIRT: {len(all_alerts)} alertas")
        return all_alerts

# Instancia global del collector
misp_csirt_collector = MISPCsirtCollector()
