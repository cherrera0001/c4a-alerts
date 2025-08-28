#!/usr/bin/env python3
"""
Script para validar la configuración de Telegram
Verifica el token, chat_id y envía un mensaje de prueba
"""

import os
import sys
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def validate_telegram_config():
    """Validar la configuración de Telegram"""
    print("🔍 Validando configuración de Telegram...")

    # Obtener variables de entorno
    bot_token = os.getenv('TELEGRAM_TOKEN')
    chat_id = os.getenv('CHAT_ID')

    if not bot_token:
        print("❌ Error: TELEGRAM_TOKEN no está configurado")
        return False

    if not chat_id:
        print("❌ Error: CHAT_ID no está configurado")
        return False

    print(f"✅ TELEGRAM_TOKEN: {'*' * (len(bot_token) - 4) + bot_token[-4:]}")
    print(f"✅ CHAT_ID: {chat_id}")

    return True

def test_bot_token(bot_token):
    """Probar si el token del bot es válido"""
    print("\n🤖 Probando token del bot...")

    try:
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/getMe",
            timeout=10
        )

        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                bot_data = bot_info['result']
                print(f"✅ Token válido!")
                print(f"   📛 Nombre del bot: {bot_data.get('first_name', 'N/A')}")
                print(f"   👤 Username: @{bot_data.get('username', 'N/A')}")
                print(f"   🆔 Bot ID: {bot_data.get('id', 'N/A')}")
                return True
            else:
                print(f"❌ Error en respuesta: {bot_info.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")
        return False

def test_chat_access(bot_token, chat_id):
    """Probar acceso al chat"""
    print(f"\n💬 Probando acceso al chat {chat_id}...")

    try:
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/getChat",
            params={'chat_id': chat_id},
            timeout=10
        )

        if response.status_code == 200:
            chat_info = response.json()
            if chat_info.get('ok'):
                chat_data = chat_info['result']
                print(f"✅ Acceso al chat exitoso!")
                print(f"   📛 Nombre: {chat_data.get('title', chat_data.get('first_name', 'N/A'))}")
                print(f"   📝 Tipo: {chat_data.get('type', 'N/A')}")
                return True
            else:
                print(f"❌ Error: {chat_info.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")
        return False

def send_test_message(bot_token, chat_id):
    """Enviar mensaje de prueba"""
    print(f"\n📤 Enviando mensaje de prueba...")

    test_message = f"""
🚨 <b>PRUEBA DE CONFIGURACIÓN</b>

✅ <b>Estado:</b> Configuración válida
🕐 <b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🔧 <b>Plataforma:</b> C4A Alerts

<i>Este es un mensaje de prueba para validar la configuración de Telegram.</i>
    """.strip()

    try:
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
                print(f"   📨 Message ID: {result['result'].get('message_id', 'N/A')}")
                return True
            else:
                print(f"❌ Error enviando mensaje: {result.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")
        return False

def main():
    """Función principal"""
    print("=" * 60)
    print("🔧 VALIDADOR DE CONFIGURACIÓN TELEGRAM")
    print("=" * 60)

    # Validar configuración básica
    if not validate_telegram_config():
        sys.exit(1)

    bot_token = os.getenv('TELEGRAM_TOKEN')
    chat_id = os.getenv('CHAT_ID')

    # Probar token del bot
    if not test_bot_token(bot_token):
        print("\n💡 Posibles soluciones:")
        print("   1. Verificar que el token sea correcto")
        print("   2. Crear un nuevo bot con @BotFather")
        print("   3. Asegurar que el bot no haya sido eliminado")
        sys.exit(1)

    # Probar acceso al chat
    if not test_chat_access(bot_token, chat_id):
        print("\n💡 Posibles soluciones:")
        print("   1. Verificar que el CHAT_ID sea correcto")
        print("   2. Asegurar que el bot esté agregado al chat/canal")
        print("   3. Verificar permisos del bot en el chat")
        sys.exit(1)

    # Enviar mensaje de prueba
    if not send_test_message(bot_token, chat_id):
        print("\n💡 Posibles soluciones:")
        print("   1. Verificar permisos de envío del bot")
        print("   2. Asegurar que el chat no esté silenciado")
        print("   3. Verificar configuración de privacidad")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("🎉 ¡CONFIGURACIÓN VÁLIDA!")
    print("✅ Telegram está listo para recibir alertas")
    print("=" * 60)

if __name__ == "__main__":
    main()
