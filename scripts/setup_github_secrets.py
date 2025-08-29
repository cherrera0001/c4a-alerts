#!/usr/bin/env python3
"""
Script para configurar GitHub Secrets para C4A Alerts Bot.
"""

import os
import sys
import requests
from typing import Dict, List

def check_github_cli():
    """Verificar si GitHub CLI está instalado."""
    try:
        import subprocess
        result = subprocess.run(['gh', '--version'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def setup_github_secrets():
    """Configurar GitHub Secrets usando GitHub CLI."""
    print("🔧 Configurando GitHub Secrets para C4A Alerts Bot")
    print("=" * 50)

    if not check_github_cli():
        print("❌ GitHub CLI no está instalado")
        print("📥 Instala desde: https://cli.github.com/")
        return False

    # Verificar autenticación
    try:
        import subprocess
        result = subprocess.run(['gh', 'auth', 'status'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ No estás autenticado en GitHub CLI")
            print("🔐 Ejecuta: gh auth login")
            return False
    except Exception as e:
        print(f"❌ Error verificando autenticación: {e}")
        return False

    # Obtener valores del usuario
    secrets = {}

    print("\n📋 Configuración de Variables:")

    # Telegram Bot Token
    secrets['TELEGRAM_TOKEN'] = input("🔑 TELEGRAM_TOKEN: ").strip()

    # Admin User ID
    admin_id = input("👤 ADMIN_USER_ID (tu ID de Telegram): ").strip()
    if not admin_id.isdigit():
        print("⚠️  ADMIN_USER_ID debe ser un número")
        return False
    secrets['ADMIN_USER_ID'] = admin_id

    # Read Only Mode
    read_only = input("🔒 READ_ONLY_MODE (true/false) [true]: ").strip().lower()
    secrets['READ_ONLY_MODE'] = read_only if read_only in ['true', 'false'] else 'true'

    # C4A API URL
    c4a_url = input("🌐 C4A_API_URL [http://localhost:8000]: ").strip()
    secrets['C4A_API_URL'] = c4a_url if c4a_url else 'http://localhost:8000'

    # Admin Chat ID (mismo que ADMIN_USER_ID por defecto)
    admin_chat = input(f"💬 ADMIN_CHAT_ID [{admin_id}]: ").strip()
    secrets['ADMIN_CHAT_ID'] = admin_chat if admin_chat else admin_id

    # Log Level
    log_level = input("📝 LOG_LEVEL (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    secrets['LOG_LEVEL'] = log_level if log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR'] else 'INFO'

    # Webhook URL (opcional)
    webhook_url = input("🔗 WEBHOOK_URL (opcional): ").strip()
    if webhook_url:
        secrets['WEBHOOK_URL'] = webhook_url

    # Webhook Secret (opcional)
    if webhook_url:
        webhook_secret = input("🔐 WEBHOOK_SECRET (opcional): ").strip()
        if webhook_secret:
            secrets['WEBHOOK_SECRET'] = webhook_secret

    print(f"\n📊 Resumen de configuración:")
    for key, value in secrets.items():
        if 'TOKEN' in key or 'SECRET' in key:
            print(f"  {key}: {'*' * len(value)}")
        else:
            print(f"  {key}: {value}")

    confirm = input("\n✅ ¿Confirmar configuración? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Configuración cancelada")
        return False

    # Configurar secrets en GitHub
    print("\n🚀 Configurando secrets en GitHub...")

    for key, value in secrets.items():
        try:
            # Usar echo para pasar el valor al comando gh
            import subprocess
            result = subprocess.run(
                ['gh', 'secret', 'set', key],
                input=value,
                text=True,
                capture_output=True
            )

            if result.returncode == 0:
                print(f"✅ {key} configurado correctamente")
            else:
                print(f"❌ Error configurando {key}: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ Error configurando {key}: {e}")
            return False

    print("\n🎉 ¡Configuración completada!")
    print("📋 Secrets configurados en GitHub:")
    for key in secrets.keys():
        print(f"  • {key}")

    return True

def show_manual_instructions():
    """Mostrar instrucciones manuales."""
    print("\n📖 INSTRUCCIONES MANUALES:")
    print("=" * 40)
    print("1. Ve a tu repositorio en GitHub")
    print("2. Settings > Secrets and variables > Actions")
    print("3. Click 'New repository secret'")
    print("4. Agrega cada variable:")
    print()
    print("🔑 TELEGRAM_TOKEN")
    print("👤 ADMIN_USER_ID")
    print("🔒 READ_ONLY_MODE")
    print("🌐 C4A_API_URL")
    print("💬 ADMIN_CHAT_ID")
    print("📝 LOG_LEVEL")
    print("🔗 WEBHOOK_URL (opcional)")
    print("🔐 WEBHOOK_SECRET (opcional)")

def main():
    """Función principal."""
    print("🔧 Configurador de GitHub Secrets - C4A Alerts Bot")
    print("=" * 55)

    print("\n📋 Opciones:")
    print("1. Configuración automática (requiere GitHub CLI)")
    print("2. Instrucciones manuales")

    option = input("\n🔢 Selecciona una opción (1 o 2): ").strip()

    if option == "1":
        setup_github_secrets()
    elif option == "2":
        show_manual_instructions()
    else:
        print("❌ Opción inválida")

if __name__ == "__main__":
    main()
