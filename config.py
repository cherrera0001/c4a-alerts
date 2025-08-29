s#!/usr/bin/env python3
"""
Configuración centralizada para C4A Alerts
Maneja variables de entorno de forma segura
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Cargar variables de entorno desde .env (solo en desarrollo)
if os.path.exists('.env'):
    load_dotenv()

class Config:
    """Configuración centralizada de la aplicación"""

    # Telegram Configuration
    TELEGRAM_TOKEN: str = os.getenv('TELEGRAM_TOKEN', '')
    CHAT_ID: str = os.getenv('CHAT_ID', '')

    # Slack Configuration
    SLACK_WEBHOOK_URL: str = os.getenv('SLACK_WEBHOOK_URL', '')
    SLACK_CHANNEL: str = os.getenv('SLACK_CHANNEL', '#alerts')

    # Database Configuration
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'sqlite:///./c4a_alerts.db')

    # API Configuration
    API_KEY: str = os.getenv('API_KEY', '')
    ENVIRONMENT: str = os.getenv('ENVIRONMENT', 'development')

    # Collectors Configuration
    MISP_URL: str = os.getenv('MISP_URL', '')
    MISP_API_KEY: str = os.getenv('MISP_API_KEY', '')
    CSIRT_URL: str = os.getenv('CSIRT_URL', '')
    CSIRT_API_KEY: str = os.getenv('CSIRT_API_KEY', '')

    # Cloud Function Configuration
    WEBHOOK_URL: str = os.getenv('WEBHOOK_URL', '')

    # Security Analysis Configuration
    FLUID_ATTACKS_TOKEN: str = os.getenv('FLUID_ATTACKS_TOKEN', '')

    @classmethod
    def validate_telegram(cls) -> bool:
        """Validar configuración de Telegram"""
        return bool(cls.TELEGRAM_TOKEN and cls.CHAT_ID)

    @classmethod
    def validate_slack(cls) -> bool:
        """Validar configuración de Slack"""
        return bool(cls.SLACK_WEBHOOK_URL)

    @classmethod
    def get_telegram_config(cls) -> dict:
        """Obtener configuración de Telegram"""
        return {
            'token': cls.TELEGRAM_TOKEN,
            'chat_id': cls.CHAT_ID
        }

    @classmethod
    def get_slack_config(cls) -> dict:
        """Obtener configuración de Slack"""
        return {
            'webhook_url': cls.SLACK_WEBHOOK_URL,
            'channel': cls.SLACK_CHANNEL
        }

    @classmethod
    def is_production(cls) -> bool:
        """Verificar si estamos en producción"""
        return cls.ENVIRONMENT.lower() == 'production'

    @classmethod
    def is_development(cls) -> bool:
        """Verificar si estamos en desarrollo"""
        return cls.ENVIRONMENT.lower() == 'development'

# Instancia global de configuración
config = Config()
