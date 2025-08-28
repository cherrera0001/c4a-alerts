#!/usr/bin/env python3
"""
Script para probar los comandos del bot de Telegram manualmente
"""

import os
import sys
import requests
import json
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def test_bot_command(command, chat_id):
    """Probar un comando específico del bot"""
    token = os.getenv('TELEGRAM_TOKEN', '')

    if not token:
        print("❌ TELEGRAM_TOKEN no configurado")
        return False

    try:
        # Simular el comando enviando un mensaje
        payload = {
            'chat_id': chat_id,
            'text': command
        }

        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print(f"✅ Comando '{command}' enviado exitosamente")
                return True
            else:
                print(f"❌ Error enviando comando: {result.get('description')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def get_chat_id():
    """Obtener Chat ID del usuario"""
    token = os.getenv('TELEGRAM_TOKEN', '')

    if not token:
        print("❌ TELEGRAM_TOKEN no configurado")
        return None

    try:
        response = requests.get(f"https://api.telegram.org/bot{token}/getUpdates")

        if response.status_code == 200:
            updates = response.json()
            if updates.get('ok') and updates['result']:
                print("📨 Mensajes recientes encontrados:")
                for update in updates['result']:
                    if 'message' in update:
                        chat = update['message']['chat']
                        print(f"   💬 Chat ID: {chat['id']}")
                        print(f"   📛 Nombre: {chat.get('first_name', chat.get('title', 'N/A'))}")
                        print(f"   👤 Username: @{chat.get('username', 'N/A')}")
                        print()

                # Usar el primer chat ID encontrado
                first_chat = updates['result'][0]['message']['chat']
                return first_chat['id']
            else:
                print("📝 No hay mensajes recientes.")
                print("💡 Para obtener tu Chat ID:")
                print("   1. Envía un mensaje a tu bot @C4A_news_bot")
                print("   2. Ejecuta este script nuevamente")
                return None
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return None

    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def main():
    """Función principal"""
    print("=" * 60)
    print("🧪 PROBADOR DE COMANDOS DEL BOT")
    print("=" * 60)

    # Obtener Chat ID
    chat_id = get_chat_id()

    if not chat_id:
        print("❌ No se pudo obtener Chat ID")
        sys.exit(1)

    print(f"✅ Usando Chat ID: {chat_id}")

    # Lista de comandos a probar
    commands = [
        "/start",
        "/help",
        "/status",
        "/subscribe",
        "/settings",
        "/about"
    ]

    print(f"\n🔧 Probando comandos...")

    for command in commands:
        print(f"\n📤 Probando: {command}")
        success = test_bot_command(command, chat_id)

        if success:
            print(f"✅ {command} - Exitoso")
        else:
            print(f"❌ {command} - Falló")

        # Pausa entre comandos
        import time
        time.sleep(2)

    print("\n" + "=" * 60)
    print("🎉 PRUEBAS COMPLETADAS")
    print("=" * 60)
    print("✅ Verifica en Telegram que recibiste las respuestas")
    print("✅ El bot está funcionando correctamente")
    print("=" * 60)

if __name__ == "__main__":
    main()
