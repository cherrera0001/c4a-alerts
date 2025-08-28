"""
Collectors package for C4A Alerts
Integraciones con fuentes de datos de Threat Intelligence
"""

from .misp_csirt import misp_csirt_collector

__all__ = ['misp_csirt_collector']
