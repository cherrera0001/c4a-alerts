#!/usr/bin/env python3
"""
Script temporal para configurar el token de Telegram
"""

import os
import requests
import json

def test_token():
    """Probar el token de Telegram"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear
    token = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_TOKEN_HERE")

    print("🔍 Probando token de Telegram...")

    try:
        # Probar que el bot existe
        response = requests.get(f"https://api.telegram.org/bot{token}/getMe")

        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                bot_data = bot_info['result']
                print(f"✅ Token válido!")
                print(f"   📛 Nombre del bot: {bot_data.get('first_name', 'N/A')}")
                print(f"   👤 Username: @{bot_data.get('username', 'N/A')}")
                print(f"   🆔 Bot ID: {bot_data.get('id', 'N/A')}")

                # Obtener updates
                updates_response = requests.get(f"https://api.telegram.org/bot{token}/getUpdates")
                if updates_response.status_code == 200:
                    updates = updates_response.json()
                    if updates.get('ok') and updates['result']:
                        print(f"\n📨 Mensajes recientes encontrados:")
                        for update in updates['result']:
                            if 'message' in update:
                                chat = update['message']['chat']
                                print(f"   💬 Chat ID: {chat['id']}")
                                print(f"   📛 Nombre: {chat.get('first_name', chat.get('title', 'N/A'))}")
                                print(f"   📝 Tipo: {chat.get('type', 'N/A')}")
                                print(f"   👤 Username: @{chat.get('username', 'N/A')}")
                                print()
                    else:
                        print(f"\n📝 No hay mensajes recientes.")
                        print(f"💡 Para obtener tu Chat ID:")
                        print(f"   1. Envía un mensaje a tu bot @{bot_data.get('username', 'N/A')}")
                        print(f"   2. Ejecuta este script nuevamente")

                return True
            else:
                print(f"❌ Error en respuesta: {bot_info.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def create_env_file():
    """Crear archivo .env con el token"""
    # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear tokens
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ ERROR: TELEGRAM_BOT_TOKEN no configurado en variables de entorno")
        return False

    env_content = f"""# C4A Alerts - Configuración de Telegram
# Generado automáticamente

# Token del bot de Telegram
TELEGRAM_TOKEN={token}

# ID del chat o canal (reemplazar con tu Chat ID)
CHAT_ID=your_chat_id_here

# Configuración adicional
# ⚠️ SEGURIDAD: DEBUG=False en producción
DEBUG=False
LOG_LEVEL=INFO
"""

    try:
        with open('.env', 'w', encoding='utf-8') as f:
            f.write(env_content)
        print(f"✅ Archivo .env creado con el token")
        print(f"📝 Ahora necesitas agregar tu Chat ID al archivo .env")
        return True
    except Exception as e:
        print(f"❌ Error creando archivo .env: {e}")
        return False

def main():
    """Función principal"""
    print("=" * 60)
    print("🔧 CONFIGURADOR DE TOKEN TELEGRAM")
    print("=" * 60)

    # Probar token
    if test_token():
        # Crear archivo .env
        create_env_file()

        print("\n" + "=" * 60)
        print("📋 PRÓXIMOS PASOS:")
        print("=" * 60)
        print("1. Envía un mensaje a tu bot @C4A_NEWS_BOT")
        print("2. Ejecuta: python scripts/setup_token.py")
        print("3. Copia el Chat ID que aparezca")
        print("4. Edita el archivo .env y reemplaza 'your_chat_id_here'")
        print("5. Ejecuta: python scripts/validate_telegram.py")
        print("=" * 60)
    else:
        print("❌ El token no es válido")

if __name__ == "__main__":
    main()
