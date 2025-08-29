#!/usr/bin/env python3
"""
🛡️ SISTEMA DE VALIDACIÓN DE ENTRADA
Implementa validación robusta para prevenir inyecciones y ataques
"""

import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ValidationLevel(str, Enum):
    """Niveles de validación."""
    STRICT = "strict"
    MODERATE = "moderate"
    LENIENT = "lenient"

@dataclass
class ValidationResult:
    """Resultado de validación."""
    is_valid: bool
    sanitized_value: Any
    errors: List[str]
    warnings: List[str]

class InputValidator:
    """Validador de entrada robusto."""

    def __init__(self, level: ValidationLevel = ValidationLevel.STRICT):
        self.level = level
        self.patterns = self._initialize_patterns()

    def _initialize_patterns(self) -> Dict[str, re.Pattern]:
        """Inicializar patrones de validación."""
        return {
            # Patrones maliciosos
            'sql_injection': re.compile(
                r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|where|set|table|database)\b)',
                re.IGNORECASE
            ),
            'xss': re.compile(
                r'<script[^>]*>.*?</script>|<[^>]*javascript:|<[^>]*on\w+\s*=|javascript:|vbscript:|data:text/html',
                re.IGNORECASE
            ),
            'path_traversal': re.compile(
                r'\.\./|\.\.\\|\.\.%2f|\.\.%5c|\.\.%2F|\.\.%5C',
                re.IGNORECASE
            ),
            'command_injection': re.compile(
                r'[;&|`$(){}[\]]|(\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|telnet|ssh|ftp)\b)',
                re.IGNORECASE
            ),
            'email': re.compile(
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            ),
            'url': re.compile(
                r'^https?://[^\s/$.?#].[^\s]*$'
            ),
            'ip_address': re.compile(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            ),
            'hash': re.compile(
                r'^[a-fA-F0-9]{32,64}$'  # MD5, SHA-1, SHA-256
            )
        }

    def validate_string(self, value: str, max_length: int = 1000) -> ValidationResult:
        """Validar string con sanitización."""
        errors = []
        warnings = []
        sanitized = value

        # Verificar longitud
        if len(value) > max_length:
            errors.append(f"String demasiado largo (máximo {max_length} caracteres)")

        # Detectar patrones maliciosos
        for pattern_name, pattern in self.patterns.items():
            if pattern_name in ['sql_injection', 'xss', 'path_traversal', 'command_injection']:
                if pattern.search(value):
                    errors.append(f"Patrón malicioso detectado: {pattern_name}")
                    if self.level == ValidationLevel.STRICT:
                        return ValidationResult(False, None, errors, warnings)

        # Sanitizar HTML
        if self.level == ValidationLevel.STRICT:
            sanitized = html.escape(value)
        elif self.level == ValidationLevel.MODERATE:
            # Remover solo tags peligrosos
            sanitized = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE)
            sanitized = re.sub(r'<[^>]*javascript:', '', sanitized, flags=re.IGNORECASE)

        # URL encode si es necesario
        if self.level == ValidationLevel.STRICT and '%' in value:
            sanitized = urllib.parse.quote(value, safe='')

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def validate_email(self, email: str) -> ValidationResult:
        """Validar email."""
        if not email:
            return ValidationResult(False, None, ["Email requerido"], [])

        pattern = self.patterns['email']
        if not pattern.match(email):
            return ValidationResult(False, None, ["Formato de email inválido"], [])

        # Verificar longitud
        if len(email) > 254:  # RFC 5321
            return ValidationResult(False, None, ["Email demasiado largo"], [])

        return ValidationResult(True, email.lower(), [], [])

    def validate_url(self, url: str) -> ValidationResult:
        """Validar URL."""
        if not url:
            return ValidationResult(False, None, ["URL requerida"], [])

        pattern = self.patterns['url']
        if not pattern.match(url):
            return ValidationResult(False, None, ["Formato de URL inválido"], [])

        # Verificar protocolos permitidos
        if not url.startswith(('http://', 'https://')):
            return ValidationResult(False, None, ["Solo se permiten URLs HTTP/HTTPS"], [])

        return ValidationResult(True, url, [], [])

    def validate_ip(self, ip: str) -> ValidationResult:
        """Validar dirección IP."""
        if not ip:
            return ValidationResult(False, None, ["IP requerida"], [])

        pattern = self.patterns['ip_address']
        if not pattern.match(ip):
            return ValidationResult(False, None, ["Formato de IP inválido"], [])

        return ValidationResult(True, ip, [], [])

    def validate_hash(self, hash_value: str) -> ValidationResult:
        """Validar hash."""
        if not hash_value:
            return ValidationResult(False, None, ["Hash requerido"], [])

        pattern = self.patterns['hash']
        if not pattern.match(hash_value):
            return ValidationResult(False, None, ["Formato de hash inválido"], [])

        return ValidationResult(True, hash_value.lower(), [], [])

    def validate_json(self, data: Any) -> ValidationResult:
        """Validar estructura JSON."""
        errors = []
        warnings = []

        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Validar clave
                key_result = self.validate_string(str(key), max_length=100)
                if not key_result.is_valid:
                    errors.extend([f"Clave inválida '{key}': {err}" for err in key_result.errors])
                    continue

                # Validar valor
                if isinstance(value, str):
                    value_result = self.validate_string(value)
                    if not value_result.is_valid:
                        errors.extend([f"Valor inválido para '{key}': {err}" for err in value_result.errors])
                        continue
                    sanitized[key_result.sanitized_value] = value_result.sanitized_value
                elif isinstance(value, (int, float, bool, type(None))):
                    sanitized[key_result.sanitized_value] = value
                elif isinstance(value, (list, dict)):
                    # Validación recursiva
                    nested_result = self.validate_json(value)
                    if not nested_result.is_valid:
                        errors.extend([f"Estructura anidada inválida en '{key}': {err}" for err in nested_result.errors])
                        continue
                    sanitized[key_result.sanitized_value] = nested_result.sanitized_value
                else:
                    errors.append(f"Tipo de dato no soportado para '{key}': {type(value)}")

        elif isinstance(data, list):
            sanitized = []
            for i, item in enumerate(data):
                item_result = self.validate_json(item)
                if not item_result.is_valid:
                    errors.extend([f"Elemento {i} inválido: {err}" for err in item_result.errors])
                    continue
                sanitized.append(item_result.sanitized_value)

        else:
            return ValidationResult(False, None, ["Tipo de dato no soportado"], [])

        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=sanitized,
            errors=errors,
            warnings=warnings
        )

    def sanitize_filename(self, filename: str) -> str:
        """Sanitizar nombre de archivo."""
        # Remover caracteres peligrosos
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limitar longitud
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            sanitized = name[:255-len(ext)-1] + ('.' + ext if ext else '')
        return sanitized

# Instancia global
input_validator = InputValidator(ValidationLevel.STRICT)

def validate_and_sanitize_input(value: Any, input_type: str = "string", **kwargs) -> ValidationResult:
    """Función helper para validar y sanitizar entrada."""
    if input_type == "email":
        return input_validator.validate_email(str(value))
    elif input_type == "url":
        return input_validator.validate_url(str(value))
    elif input_type == "ip":
        return input_validator.validate_ip(str(value))
    elif input_type == "hash":
        return input_validator.validate_hash(str(value))
    elif input_type == "json":
        return input_validator.validate_json(value)
    elif input_type == "filename":
        sanitized = input_validator.sanitize_filename(str(value))
        return ValidationResult(True, sanitized, [], [])
    else:
        max_length = kwargs.get('max_length', 1000)
        return input_validator.validate_string(str(value), max_length)
