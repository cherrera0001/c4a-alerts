"""
C4A Alerts - Paquete principal
Sistema de alertas de seguridad y threat intelligence
"""

__version__ = "2.0.0"
__author__ = "C4A Security Team"

# Importaciones principales - manejar errores de módulos faltantes
try:
    from .validators import validate_url, sanitize_cve_id
    HAS_VALIDATORS = True
except ImportError:
    HAS_VALIDATORS = False
    
try:
    from .models import AlertModel, ThreatIntelModel
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False

try:
    from .core import Orchestrator
    HAS_CORE = True
except ImportError:
    HAS_CORE = False

# Exportar solo lo que está disponible
__all__ = []

if HAS_VALIDATORS:
    __all__.extend(['validate_url', 'sanitize_cve_id'])

if HAS_MODELS:
    __all__.extend(['AlertModel', 'ThreatIntelModel'])
    
if HAS_CORE:
    __all__.extend(['Orchestrator'])


def check_dependencies():
    """Verifica que todas las dependencias críticas estén disponibles"""
    missing = []
    
    if not HAS_VALIDATORS:
        missing.append("validators")
    if not HAS_MODELS:
        missing.append("models")
    if not HAS_CORE:
        missing.append("core")
    
    return missing
