#!/usr/bin/env python3
"""
Script de configuración rápida para C4A Alerts Bot.
Guía paso a paso para configurar todo el sistema.
"""

import os
import sys
from pathlib import Path

def print_banner():
    """Imprimir banner del script."""
    print("=" * 60)
    print("🚀 CONFIGURACIÓN RÁPIDA - C4A ALERTS BOT")
    print("=" * 60)
    print("Este script te guiará para configurar tu bot de Telegram")
    print("con acceso restringido y detección de malware.")
    print()

def get_telegram_token():
    """Obtener token de Telegram."""
    print("🔑 PASO 1: Token de Telegram Bot")
    print("-" * 35)
    print("1. Ve a @BotFather en Telegram")
    print("2. Envía /newbot")
    print("3. Sigue las instrucciones")
    print("4. Copia el token que te da")
    print()

    token = input("🔑 Pega tu TELEGRAM_TOKEN aquí: ").strip()

    if not token or len(token) < 20:
        print("❌ Token inválido. Debe tener al menos 20 caracteres.")
        return None

    return token

def get_user_id():
    """Obtener ID de usuario."""
    print("\n👤 PASO 2: Tu ID de Usuario")
    print("-" * 30)
    print("Opciones para obtener tu ID:")
    print("1. Usar @userinfobot en Telegram")
    print("2. Enviar mensaje a tu bot y usar getUpdates")
    print("3. Usar el script get_telegram_user_id.py")
    print()

    user_id = input("👤 Ingresa tu ADMIN_USER_ID: ").strip()

    if not user_id.isdigit():
        print("❌ ID debe ser un número")
        return None

    return user_id

def setup_environment():
    """Configurar variables de entorno."""
    print("\n🔧 PASO 3: Configuración del Sistema")
    print("-" * 35)

    # Obtener valores
    token = get_telegram_token()
    if not token:
        return False

    user_id = get_user_id()
    if not user_id:
        return False

    # Configuración por defecto
    read_only = "true"
    c4a_url = "http://localhost:8000"
    log_level = "INFO"

    print(f"\n📊 Configuración por defecto:")
    print(f"  READ_ONLY_MODE: {read_only}")
    print(f"  C4A_API_URL: {c4a_url}")
    print(f"  LOG_LEVEL: {log_level}")

    change = input("\n¿Cambiar configuración por defecto? (y/N): ").strip().lower()

    if change == 'y':
        read_only = input("🔒 READ_ONLY_MODE (true/false) [true]: ").strip().lower()
        read_only = read_only if read_only in ['true', 'false'] else 'true'

        c4a_url = input("🌐 C4A_API_URL [http://localhost:8000]: ").strip()
        c4a_url = c4a_url if c4a_url else 'http://localhost:8000'

        log_level = input("📝 LOG_LEVEL (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip().upper()
        log_level = log_level if log_level in ['DEBUG', 'INFO', 'WARNING', 'ERROR'] else 'INFO'

    # Crear archivo .env
    env_content = f"""# C4A Alerts Bot - Variables de Entorno
# Archivo generado automáticamente
# NO subir a GitHub (está en .gitignore)

TELEGRAM_TOKEN={token}
ADMIN_USER_ID={user_id}
READ_ONLY_MODE={read_only}
C4A_API_URL={c4a_url}
ADMIN_CHAT_ID={user_id}
LOG_LEVEL={log_level}
"""

    # Guardar archivo
    env_path = Path('cloud-function/.env')

    try:
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)

        print(f"\n✅ Archivo .env creado en: {env_path}")
        return True

    except Exception as e:
        print(f"❌ Error creando archivo: {e}")
        return False

def show_next_steps():
    """Mostrar próximos pasos."""
    print("\n🎯 PRÓXIMOS PASOS:")
    print("=" * 25)
    print("1. ✅ Variables configuradas")
    print("2. 🚀 Iniciar C4A Alerts API:")
    print("   python -m uvicorn c4aalerts.app.api.main:app --reload --host 0.0.0.0 --port 8000")
    print("3. 🤖 Iniciar Bot de Telegram:")
    print("   cd cloud-function")
    print("   python telegram_webhook.py")
    print("4. 📱 Probar el bot:")
    print("   Envía /start a tu bot")
    print("5. 🔒 Probar acceso restringido:")
    print("   Pide a alguien más que envíe un mensaje")
    print()
    print("📚 DOCUMENTACIÓN:")
    print("• README.md - Información general")
    print("• docs/ - Documentación detallada")
    print("• scripts/ - Scripts de utilidad")

def show_github_setup():
    """Mostrar configuración para GitHub."""
    print("\n🌐 CONFIGURACIÓN PARA PRODUCCIÓN (GitHub):")
    print("=" * 45)
    print("Para desplegar en GitHub Actions:")
    print("1. Ejecuta: python scripts/setup_github_secrets.py")
    print("2. O configura manualmente en GitHub:")
    print("   Settings > Secrets and variables > Actions")
    print("3. Agrega las mismas variables que configuraste")
    print("4. Haz push de tu código")
    print("5. Los GitHub Actions se ejecutarán automáticamente")

def main():
    """Función principal."""
    print_banner()

    print("📋 Este script te ayudará a configurar:")
    print("• Token de Telegram Bot")
    print("• Tu ID de usuario")
    print("• Variables de entorno")
    print("• Acceso restringido")
    print()

    start = input("🚀 ¿Comenzar configuración? (Y/n): ").strip().lower()
    if start in ['n', 'no']:
        print("❌ Configuración cancelada")
        return

    if setup_environment():
        show_next_steps()
        show_github_setup()

        print("\n" + "=" * 60)
        print("🎉 ¡CONFIGURACIÓN COMPLETADA!")
        print("=" * 60)
        print("Tu bot está listo para usar con acceso restringido.")
        print("Solo tú podrás enviar contenido, los demás solo leerán.")
    else:
        print("\n❌ Configuración fallida")
        print("Revisa los errores e intenta nuevamente.")

if __name__ == "__main__":
    main()
