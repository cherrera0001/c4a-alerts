#!/usr/bin/env python3
"""
Script para crear el archivo .env con la configuración correcta
"""

import os
from pathlib import Path

def create_env_file():
    """Crear archivo .env con la configuración de Telegram"""

    env_content = """# C4A Alerts - Configuración de Variables de Entorno
# Copia este archivo como .env y configura tus valores

# =============================================================================
# CONFIGURACIÓN DE TELEGRAM
# =============================================================================
TELEGRAM_TOKEN=7330329737:AAGubXJVl7x4KgmaJ916V0HjNm_ErMQr-_c
CHAT_ID=551008154

# =============================================================================
# CONFIGURACIÓN DE SLACK (OPCIONAL)
# =============================================================================
SLACK_WEBHOOK_URL=your_slack_webhook_url_here
SLACK_CHANNEL=#alerts

# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS (OPCIONAL)
# =============================================================================
DATABASE_URL=sqlite:///./c4a_alerts.db

# =============================================================================
# CONFIGURACIÓN DE API
# =============================================================================
API_KEY=your_api_key_here
ENVIRONMENT=development

# =============================================================================
# CONFIGURACIÓN DE COLECTORES
# =============================================================================
MISP_URL=your_misp_url_here
MISP_API_KEY=your_misp_api_key_here
CSIRT_URL=your_csirt_url_here
CSIRT_API_KEY=your_csirt_api_key_here
"""

    env_path = Path('.env')

    try:
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)

        print("✅ Archivo .env creado exitosamente!")
        print(f"📁 Ubicación: {env_path.absolute()}")
        print("\n📋 Contenido del archivo:")
        print("=" * 50)
        print(env_content)
        print("=" * 50)

        return True

    except Exception as e:
        print(f"❌ Error creando archivo .env: {e}")
        return False

def main():
    """Función principal"""
    print("=" * 50)
    print("📝 CREAR ARCHIVO .ENV")
    print("=" * 50)

    if create_env_file():
        print("\n🎉 ¡Configuración completada!")
        print("💡 Ahora puedes ejecutar: python scripts/validate_telegram.py")
    else:
        print("\n❌ Error en la configuración")

if __name__ == "__main__":
    main()
