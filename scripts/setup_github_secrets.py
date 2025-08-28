#!/usr/bin/env python3
"""
Script para configurar secrets de GitHub
Guía al usuario para configurar los secrets necesarios
"""

import os
import sys
from pathlib import Path

def print_banner():
    """Imprimir banner del script"""
    print("=" * 60)
    print("🔐 CONFIGURADOR DE SECRETS DE GITHUB")
    print("=" * 60)
    print("Este script te ayudará a configurar los secrets necesarios")
    print("para que C4A Alerts funcione correctamente en GitHub Actions.")
    print()

def print_secrets_guide():
    """Imprimir guía de secrets"""
    print("📋 SECRETS REQUERIDOS PARA GITHUB:")
    print("=" * 40)

    secrets = {
        "TELEGRAM_TOKEN": {
            "description": "Token del bot de Telegram",
            "value": "7330329737:AAGubXJVl7x4KgmaJ916V0HjNm_ErMQr-_c",
            "how_to_get": "Desde @BotFather en Telegram"
        },
        "CHAT_ID": {
            "description": "ID del chat de Telegram",
            "value": "551008154",
            "how_to_get": "Tu Chat ID personal"
        },
        "SLACK_WEBHOOK_URL": {
            "description": "URL del webhook de Slack (opcional)",
            "value": "https://hooks.slack.com/services/...",
            "how_to_get": "Desde la configuración de Slack"
        },
        "VERCEL_TOKEN": {
            "description": "Token de Vercel para deployment",
            "value": "vercel_...",
            "how_to_get": "Desde la configuración de Vercel"
        },
        "VERCEL_ORG_ID": {
            "description": "ID de la organización de Vercel",
            "value": "team_...",
            "how_to_get": "Desde la configuración de Vercel"
        },
        "VERCEL_PROJECT_ID": {
            "description": "ID del proyecto de Vercel",
            "value": "prj_...",
            "how_to_get": "Desde la configuración de Vercel"
        },
        "GOOGLE_CREDENTIALS": {
            "description": "Credenciales de Google Cloud (JSON)",
            "value": "{\"type\": \"service_account\", ...}",
            "how_to_get": "Desde Google Cloud Console"
        }
    }

    for secret_name, info in secrets.items():
        print(f"🔑 {secret_name}")
        print(f"   📝 Descripción: {info['description']}")
        print(f"   💡 Cómo obtener: {info['how_to_get']}")
        print(f"   📋 Valor actual: {info['value']}")
        print()

def print_setup_instructions():
    """Imprimir instrucciones de configuración"""
    print("📋 CÓMO CONFIGURAR LOS SECRETS:")
    print("=" * 40)
    print("1. Ve a tu repositorio en GitHub")
    print("2. Haz clic en 'Settings' (Configuración)")
    print("3. En el menú lateral, haz clic en 'Secrets and variables'")
    print("4. Selecciona 'Actions'")
    print("5. Haz clic en 'New repository secret'")
    print("6. Agrega cada secret con su nombre y valor")
    print()
    print("🔗 URL: https://github.com/TU_USUARIO/TU_REPO/settings/secrets/actions")
    print()

def print_local_vs_production():
    """Explicar diferencias entre local y producción"""
    print("🏠 DESARROLLO LOCAL vs 🌐 PRODUCCIÓN:")
    print("=" * 40)
    print("🏠 DESARROLLO LOCAL:")
    print("   - Usa archivo .env")
    print("   - Variables de entorno locales")
    print("   - Configuración en scripts/")
    print()
    print("🌐 PRODUCCIÓN (GitHub Actions):")
    print("   - Usa GitHub Secrets")
    print("   - Variables de entorno seguras")
    print("   - Configuración automática")
    print()

def create_env_template():
    """Crear template de .env para desarrollo local"""
    env_content = """# C4A Alerts - Variables de Entorno (DESARROLLO LOCAL)
# Este archivo NO se sube a GitHub (está en .gitignore)

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
# CONFIGURACIÓN DE BASE DE DATOS
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

# =============================================================================
# CONFIGURACIÓN DE CLOUD FUNCTION
# =============================================================================
WEBHOOK_URL=your_webhook_url_here
"""

    env_path = Path('.env')

    if env_path.exists():
        print("✅ Archivo .env ya existe")
    else:
        try:
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write(env_content)
            print("✅ Archivo .env creado")
        except Exception as e:
            print(f"❌ Error creando .env: {e}")

def main():
    """Función principal"""
    print_banner()

    print_secrets_guide()
    print_setup_instructions()
    print_local_vs_production()

    print("🔧 CONFIGURACIÓN LOCAL:")
    create_env_template()

    print("\n" + "=" * 60)
    print("🎉 ¡CONFIGURACIÓN COMPLETADA!")
    print("=" * 60)
    print("📋 Próximos pasos:")
    print("1. Configura los secrets en GitHub")
    print("2. Haz push de tu código")
    print("3. Los GitHub Actions se ejecutarán automáticamente")
    print("4. Revisa los logs en la pestaña 'Actions'")
    print()

if __name__ == "__main__":
    main()
