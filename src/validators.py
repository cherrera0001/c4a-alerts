"""
Módulo de validación para C4A Alerts
Contiene funciones de validación y sanitización de datos
"""
import re
from typing import Optional
from urllib.parse import urlparse


def validate_url(url: str) -> bool:
    """
    Valida si una URL tiene un formato válido
    
    Args:
        url: URL a validar
        
    Returns:
        bool: True si la URL es válida, False en caso contrario
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def sanitize_cve_id(cve_id: str) -> Optional[str]:
    """
    Sanitiza y valida un CVE ID
    
    Args:
        cve_id: CVE ID a sanitizar
        
    Returns:
        str: CVE ID sanitizado o None si es inválido
    """
    if not cve_id:
        return None
    
    # Patrón para CVE: CVE-YYYY-NNNN (donde NNNN puede ser 4+ dígitos)
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
    
    # Limpiar espacios y convertir a mayúsculas
    clean_cve = cve_id.strip().upper()
    
    if cve_pattern.match(clean_cve):
        return clean_cve
    
    return None


def sanitize_string(input_str: str, max_length: int = 1000) -> str:
    """
    Sanitiza una string removiendo caracteres peligrosos
    
    Args:
        input_str: String a sanitizar
        max_length: Longitud máxima permitida
        
    Returns:
        str: String sanitizada
    """
    if not input_str:
        return ""
    
    # Remover caracteres de control y limitar longitud
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_str)
    return sanitized[:max_length].strip()


def validate_severity_score(score: float) -> bool:
    """
    Valida que un score de severidad esté en el rango válido
    
    Args:
        score: Score a validar
        
    Returns:
        bool: True si el score es válido (0.0-10.0)
    """
    return isinstance(score, (int, float)) and 0.0 <= score <= 10.0


def validate_email(email: str) -> bool:
    """
    Valida formato de email básico
    
    Args:
        email: Email a validar
        
    Returns:
        bool: True si tiene formato válido
    """
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(email_pattern.match(email.strip()))
