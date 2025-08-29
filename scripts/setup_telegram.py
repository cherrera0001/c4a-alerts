#!/usr/bin/env python3
"""
Script interactivo para configurar Telegram
Guía al usuario paso a paso para configurar las notificaciones
"""

import os
import sys
import requests
import json
from pathlib import Path

def print_banner():
    """Mostrar banner del script"""
    print("=" * 70)
    print("🤖 CONFIGURADOR DE TELEGRAM - C4A Alerts")
    print("=" * 70)
    print("Este script te guiará paso a paso para configurar las")
    print("notificaciones de Telegram para C4A Alerts.")
    print("=" * 70)

def get_user_input(prompt, default=""):
    """Obtener entrada del usuario con valor por defecto"""
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()

def create_bot_instructions():
    """Mostrar instrucciones para crear un bot"""
    print("\n📋 PASO 1: Crear un bot de Telegram")
    print("-" * 50)
    print("1. Abre Telegram y busca @BotFather")
    print("2. Envía el comando: /newbot")
    print("3. Sigue las instrucciones para crear tu bot")
    print("4. Guarda el token que te proporciona")
    print("5. El token se ve así: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz")

    input("\nPresiona Enter cuando hayas creado el bot...")

def get_chat_id_instructions():
    """Mostrar instrucciones para obtener el chat_id"""
    print("\n📋 PASO 2: Obtener el Chat ID")
    print("-" * 50)
    print("Hay varias formas de obtener el chat_id:")
    print("\nOpción A - Para chat privado:")
    print("1. Envía un mensaje a tu bot")
    print("2. Visita: https://api.telegram.org/bot<TOKEN>/getUpdates")
    print("3. Busca el 'chat' -> 'id' en la respuesta")

    print("\nOpción B - Para canal/grupo:")
    print("1. Agrega tu bot al canal/grupo")
    print("2. Envía un mensaje al canal/grupo")
    print("3. Visita: https://api.telegram.org/bot<TOKEN>/getUpdates")
    print("4. Busca el 'chat' -> 'id' en la respuesta")

    print("\nOpción C - Usar @userinfobot:")
    print("1. Busca @userinfobot en Telegram")
    print("2. Envía cualquier mensaje")
    print("3. Te mostrará tu ID de usuario")

def test_telegram_config(bot_token, chat_id):
    """Probar la configuración de Telegram"""
    print(f"\n🧪 Probando configuración...")

    try:
        # Probar token del bot
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/getMe",
            timeout=10
        )

        if response.status_code != 200:
            print(f"❌ Error con el token: {response.text}")
            return False

        bot_info = response.json()
        if not bot_info.get('ok'):
            print(f"❌ Token inválido: {bot_info.get('description')}")
            return False

        print(f"✅ Bot verificado: @{bot_info['result']['username']}")

        # Probar envío de mensaje
        test_message = f"""
🔧 <b>Configuración Exitosa - C4A Alerts</b>

✅ <b>Estado:</b> Configuración validada
🤖 <b>Bot:</b> @{bot_info['result']['username']}
💬 <b>Chat ID:</b> {chat_id}

<i>¡Las notificaciones de C4A Alerts están listas!</i>
        """.strip()

        payload = {
            'chat_id': chat_id,
            'text': test_message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': True
        }

        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Mensaje de prueba enviado exitosamente!")
                return True
            else:
                print(f"❌ Error enviando mensaje: {result.get('description')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")
        return False

def save_config(bot_token, chat_id):
    """Guardar configuración en archivo .env"""
    env_content = f"""# C4A Alerts - Configuración de Telegram
# Generado automáticamente por setup_telegram.py

# Token del bot de Telegram
TELEGRAM_TOKEN={bot_token}

# ID del chat o canal
CHAT_ID={chat_id}

# Configuración adicional
# ⚠️ SEGURIDAD: DEBUG=False en producción
DEBUG=False
LOG_LEVEL=INFO
"""

    env_file = Path('.env')

    # Si ya existe un .env, preguntar si sobrescribir
    if env_file.exists():
        overwrite = get_user_input(
            "El archivo .env ya existe. ¿Sobrescribir? (y/N)",
            "N"
        ).lower()

        if overwrite not in ['y', 'yes', 'sí', 'si']:
            print("❌ Configuración cancelada")
            return False

    try:
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(env_content)
        print(f"✅ Configuración guardada en {env_file}")
        return True
    except Exception as e:
        print(f"❌ Error guardando configuración: {e}")
        return False

def main():
    """Función principal"""
    print_banner()

    # Verificar si ya está configurado
    if os.getenv('TELEGRAM_TOKEN') and os.getenv('CHAT_ID'):
        print("⚠️  Telegram ya está configurado!")
        use_existing = get_user_input(
            "¿Usar configuración existente? (Y/n)",
            "Y"
        ).lower()

        if use_existing in ['y', 'yes', 'sí', 'si', '']:
            print("✅ Usando configuración existente")
            return

    # Paso 1: Crear bot
    create_bot_instructions()

    # Obtener token
    bot_token = get_user_input(
        "Ingresa el token de tu bot de Telegram"
    )

    if not bot_token:
        print("❌ Token requerido")
        sys.exit(1)

    # Paso 2: Obtener chat_id
    get_chat_id_instructions()

    # Obtener chat_id
    chat_id = get_user_input(
        "Ingresa el Chat ID"
    )

    if not chat_id:
        print("❌ Chat ID requerido")
        sys.exit(1)

    # Probar configuración
    print(f"\n🧪 Probando configuración...")
    if not test_telegram_config(bot_token, chat_id):
        print("\n❌ La configuración no funciona correctamente")
        print("💡 Verifica:")
        print("   - Que el token sea correcto")
        print("   - Que el chat_id sea correcto")
        print("   - Que el bot esté agregado al chat")
        sys.exit(1)

    # Guardar configuración
    print(f"\n💾 Guardando configuración...")
    if save_config(bot_token, chat_id):
        print("\n" + "=" * 70)
        print("🎉 ¡CONFIGURACIÓN COMPLETADA!")
        print("=" * 70)
        print("✅ Telegram está configurado y funcionando")
        print("✅ Las alertas se enviarán automáticamente")
        print("✅ Puedes probar con: python scripts/validate_telegram.py")
        print("=" * 70)
    else:
        print("❌ Error guardando configuración")
        sys.exit(1)

if __name__ == "__main__":
    main()
