#!/usr/bin/env python3
"""
Script simple para obtener Chat ID
"""

import requests
import json

def get_chat_id():
    """Obtener Chat ID del usuario"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear tokens
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN no configurado en variables de entorno")
        return False

    try:
        print("🔍 Consultando mensajes recientes...")
        response = requests.get(f"https://api.telegram.org/bot{token}/getUpdates")

        if response.status_code == 200:
            data = response.json()
            print(f"📊 Respuesta completa: {json.dumps(data, indent=2)}")

            if data.get('ok') and data['result']:
                print("\n📨 Mensajes encontrados:")
                for update in data['result']:
                    if 'message' in update:
                        chat = update['message']['chat']
                        print(f"   💬 Chat ID: {chat['id']}")
                        print(f"   📛 Nombre: {chat.get('first_name', chat.get('title', 'N/A'))}")
                        print(f"   👤 Username: @{chat.get('username', 'N/A')}")
                        print(f"   📝 Tipo: {chat.get('type', 'N/A')}")
                        print()

                # Usar el primer chat ID encontrado
                first_chat = data['result'][0]['message']['chat']
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
    print("=" * 50)
    print("🔍 OBTENER CHAT ID")
    print("=" * 50)

    chat_id = get_chat_id()

    if chat_id:
        print(f"✅ Chat ID encontrado: {chat_id}")
        print(f"📝 Agrega este valor a tu archivo .env")
    else:
        print("❌ No se pudo obtener Chat ID")

if __name__ == "__main__":
    main()
