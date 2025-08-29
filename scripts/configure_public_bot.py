#!/usr/bin/env python3
"""
Script para configurar el bot de Telegram para uso público
"""

import requests
import json

def configure_bot_commands():
    """Configurar comandos del bot"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear tokens
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN no configurado en variables de entorno")
        print("   Configura TELEGRAM_BOT_TOKEN en tu archivo .env")
        return False

    commands = [
        {
            "command": "start",
            "description": "🚀 Iniciar C4A Alerts - Plataforma de Threat Intelligence"
        },
        {
            "command": "help",
            "description": "❓ Mostrar ayuda y comandos disponibles"
        },
        {
            "command": "status",
            "description": "📊 Ver estado del sistema y alertas recientes"
        },
        {
            "command": "subscribe",
            "description": "🔔 Suscribirse a alertas de seguridad"
        },
        {
            "command": "unsubscribe",
            "description": "🔕 Cancelar suscripción a alertas"
        },
        {
            "command": "settings",
            "description": "⚙️ Configurar preferencias de notificaciones"
        },
        {
            "command": "about",
            "description": "ℹ️ Información sobre C4A Alerts"
        }
    ]

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/setMyCommands",
            json={"commands": commands}
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Comandos del bot configurados exitosamente")
                return True
            else:
                print(f"❌ Error configurando comandos: {result.get('description')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def set_bot_description():
    """Configurar descripción del bot"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear tokens
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN no configurado en variables de entorno")
        return False

    description = """🔒 C4A Alerts - Threat Intelligence Platform

🚀 Plataforma avanzada de inteligencia de amenazas cibernéticas

✨ Características:
• Alertas en tiempo real de amenazas de seguridad
• Análisis de vulnerabilidades y CVEs
• Monitoreo de fuentes de inteligencia
• Notificaciones personalizables
• Dashboard interactivo

🔔 Recibe alertas sobre:
• Nuevas vulnerabilidades críticas
• Amenazas emergentes
• Actualizaciones de seguridad
• Análisis de malware
• Tendencias de ciberseguridad

💡 Comandos disponibles:
/start - Iniciar el bot
/help - Ver ayuda
/status - Estado del sistema
/subscribe - Suscribirse a alertas
/settings - Configurar preferencias

🌐 Más información: https://github.com/your-repo/c4a-alerts

Desarrollado con ❤️ para la comunidad de ciberseguridad"""

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/setMyDescription",
            json={"description": description}
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Descripción del bot configurada")
                return True
            else:
                print(f"❌ Error configurando descripción: {result.get('description')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def set_bot_short_description():
    """Configurar descripción corta del bot"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear tokens
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN no configurado en variables de entorno")
        return False

    short_description = "🔒 Plataforma de Threat Intelligence - Alertas de seguridad en tiempo real"

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/setMyShortDescription",
            json={"short_description": short_description}
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Descripción corta configurada")
                return True
            else:
                print(f"❌ Error configurando descripción corta: {result.get('description')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def get_bot_info():
    """Obtener información del bot"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear tokens
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN no configurado en variables de entorno")
        return False

    try:
        response = requests.get(f"https://api.telegram.org/bot{token}/getMe")

        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                bot_data = bot_info['result']
                print("=" * 60)
                print("🤖 INFORMACIÓN DEL BOT")
                print("=" * 60)
                print(f"📛 Nombre: {bot_data.get('first_name', 'N/A')}")
                print(f"👤 Username: @{bot_data.get('username', 'N/A')}")
                print(f"🆔 Bot ID: {bot_data.get('id', 'N/A')}")
                print(f"🔗 Link: https://t.me/{bot_data.get('username', 'N/A')}")
                print(f"✅ Can Join Groups: {bot_data.get('can_join_groups', 'N/A')}")
                print(f"✅ Can Read All Group Messages: {bot_data.get('can_read_all_group_messages', 'N/A')}")
                print(f"✅ Supports Inline Queries: {bot_data.get('supports_inline_queries', 'N/A')}")
                print("=" * 60)
                return True
            else:
                print(f"❌ Error obteniendo información: {bot_info.get('description')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Función principal"""
    print("=" * 60)
    print("🔧 CONFIGURADOR DE BOT PÚBLICO")
    print("=" * 60)

    # Obtener información actual del bot
    get_bot_info()

    print("\n🔧 Configurando bot para uso público...")

    # Configurar comandos
    if configure_bot_commands():
        print("✅ Comandos configurados")
    else:
        print("❌ Error configurando comandos")

    # Configurar descripción
    if set_bot_description():
        print("✅ Descripción configurada")
    else:
        print("❌ Error configurando descripción")

    # Configurar descripción corta
    if set_bot_short_description():
        print("✅ Descripción corta configurada")
    else:
        print("❌ Error configurando descripción corta")

    print("\n" + "=" * 60)
    print("🎉 CONFIGURACIÓN COMPLETADA")
    print("=" * 60)
    print("✅ Tu bot está listo para uso público")
    print("✅ Cualquier persona puede acceder usando:")
    print("   https://t.me/C4A_news_bot")
    print("✅ Los usuarios pueden usar /start para comenzar")
    print("✅ Configura el sistema de suscripciones en tu backend")
    print("=" * 60)

if __name__ == "__main__":
    main()
