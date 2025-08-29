#!/usr/bin/env python3
"""
Script para configurar variables de entorno locales para C4A Alerts Bot.
"""

import os
from pathlib import Path

def create_env_file():
    """Crear archivo .env con las variables necesarias."""
    print("🔧 Configurando Variables de Entorno Locales")
    print("=" * 45)

    # Obtener valores del usuario
    env_vars = {}

    print("\n📋 Configuración de Variables:")

    # Telegram Bot Token
    env_vars['TELEGRAM_TOKEN'] = input("🔑 TELEGRAM_TOKEN: ").strip()

    # Admin User ID
    admin_id = input("👤 ADMIN_USER_ID (tu ID de Telegram): ").strip()
    if not admin_id.isdigit():
        print("⚠️  ADMIN_USER_ID debe ser un número")
        return False
    env_vars['ADMIN_USER_ID'] = admin_id

    # Read Only Mode
    read_only = input("🔒 READ_ONLY_MODE (true/false) [true]: ").strip().lower()
    env_vars['READ_ONLY_MODE'] = read_only if read_only in ['true', 'false'] else 'true'

    # C4A API URL
    c4a_url = input("🌐 C4A_API_URL [http://localhost:8000]: ").strip()
    env_vars['C4A_API_URL'] = c4a_url if c4a_url else 'http://localhost:8000'

    # Admin Chat ID (mismo que ADMIN_USER_ID por defecto)
    admin_chat = input(f"💬 ADMIN_CHAT_ID [{admin_id}]: ").strip()
    env_vars['ADMIN_CHAT_ID'] = admin_chat if admin_chat else admin_id

    # Log Level
    log_level = input("📝 LOG_LEVEL (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
    env_vars['LOG_LEVEL'] = log_level if log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR'] else 'INFO'

    # Webhook URL (opcional)
    webhook_url = input("🔗 WEBHOOK_URL (opcional): ").strip()
    if webhook_url:
        env_vars['WEBHOOK_URL'] = webhook_url

    # Webhook Secret (opcional)
    if webhook_url:
        webhook_secret = input("🔐 WEBHOOK_SECRET (opcional): ").strip()
        if webhook_secret:
            env_vars['WEBHOOK_SECRET'] = webhook_secret

    # Mostrar resumen
    print(f"\n📊 Resumen de configuración:")
    for key, value in env_vars.items():
        if 'TOKEN' in key or 'SECRET' in key:
            print(f"  {key}: {'*' * len(value)}")
        else:
            print(f"  {key}: {value}")

    confirm = input("\n✅ ¿Confirmar configuración? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Configuración cancelada")
        return False

    # Crear archivo .env
    env_content = "# C4A Alerts Bot - Variables de Entorno\n"
    env_content += "# Archivo generado automáticamente\n"
    env_content += "# NO subir a GitHub (está en .gitignore)\n\n"

    for key, value in env_vars.items():
        env_content += f"{key}={value}\n"

    # Guardar en cloud-function/.env
    env_path = Path('cloud-function/.env')

    try:
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)

        print(f"\n✅ Archivo .env creado en: {env_path}")
        print("🔒 El archivo está protegido por .gitignore")

        # Mostrar contenido (sin tokens)
        print(f"\n📄 Contenido del archivo:")
        for key, value in env_vars.items():
            if 'TOKEN' in key or 'SECRET' in key:
                print(f"{key}=***")
            else:
                print(f"{key}={value}")

        return True

    except Exception as e:
        print(f"❌ Error creando archivo .env: {e}")
        return False

def show_instructions():
    """Mostrar instrucciones de uso."""
    print("\n📖 INSTRUCCIONES DE USO:")
    print("=" * 35)
    print("1. El archivo .env se creó en cloud-function/.env")
    print("2. Las variables están disponibles para el bot")
    print("3. Para usar en producción, configura GitHub Secrets")
    print("4. El archivo .env NO se sube a GitHub")
    print()
    print("🚀 Para ejecutar el bot:")
    print("   cd cloud-function")
    print("   python telegram_webhook.py")
    print()
    print("🔧 Para cambiar configuración:")
    print("   Edita cloud-function/.env manualmente")
    print("   O ejecuta este script nuevamente")

def main():
    """Función principal."""
    print("🔧 Configurador de Variables Locales - C4A Alerts Bot")
    print("=" * 55)

    if create_env_file():
        show_instructions()
    else:
        print("❌ Configuración fallida")

if __name__ == "__main__":
    main()
