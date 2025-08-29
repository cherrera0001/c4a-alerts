#!/usr/bin/env python3
"""
Script para obtener el ID de usuario de Telegram.
Útil para configurar el ADMIN_USER_ID en el bot.
"""

import requests
import os
from typing import Optional

def get_user_id_from_username(username: str, bot_token: str) -> Optional[int]:
    """Obtener ID de usuario desde username usando el bot."""
    try:
        # Intentar obtener información del usuario
        url = f"https://api.telegram.org/bot{bot_token}/getChat"
        response = requests.post(url, json={"chat_id": f"@{username}"})

        if response.status_code == 200:
            data = response.json()
            if data.get("ok"):
                return data["result"]["id"]

        return None
    except Exception as e:
        print(f"Error obteniendo ID de usuario: {e}")
        return None

def get_my_id_from_bot(bot_token: str) -> Optional[int]:
    """Obtener tu propio ID enviando un mensaje al bot."""
    try:
        # Obtener información del bot
        url = f"https://api.telegram.org/bot{bot_token}/getMe"
        response = requests.get(url)

        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get("ok"):
                bot_username = bot_info["result"]["username"]
                print(f"🤖 Bot encontrado: @{bot_username}")
                print(f"📝 Envía un mensaje a @{bot_username} y luego ejecuta este script")
                return None

        return None
    except Exception as e:
        print(f"Error obteniendo información del bot: {e}")
        return None

def main():
    """Función principal."""
    print("🆔 Obtener ID de Usuario de Telegram")
    print("=" * 40)

    # Obtener token del bot
    bot_token = input("🔑 Ingresa el token de tu bot: ").strip()

    if not bot_token:
        print("❌ Token requerido")
        return

    print("\n📋 Opciones:")
    print("1. Obtener ID desde username")
    print("2. Obtener tu ID enviando mensaje al bot")

    option = input("\n🔢 Selecciona una opción (1 o 2): ").strip()

    if option == "1":
        username = input("👤 Ingresa el username (sin @): ").strip()
        if username.startswith("@"):
            username = username[1:]

        user_id = get_user_id_from_username(username, bot_token)
        if user_id:
            print(f"✅ ID encontrado: {user_id}")
            print(f"📝 Configura ADMIN_USER_ID={user_id} en tu .env")
        else:
            print("❌ No se pudo obtener el ID")

    elif option == "2":
        print("\n📝 Instrucciones:")
        print("1. Envía un mensaje a tu bot")
        print("2. Luego ejecuta este script")

        input("\n⏸️  Presiona Enter después de enviar el mensaje...")

        # Obtener actualizaciones recientes
        try:
            url = f"https://api.telegram.org/bot{bot_token}/getUpdates"
            response = requests.get(url)

            if response.status_code == 200:
                data = response.json()
                if data.get("ok") and data["result"]:
                    # Obtener el último mensaje
                    last_update = data["result"][-1]
                    if "message" in last_update:
                        user_id = last_update["message"]["from"]["id"]
                        username = last_update["message"]["from"].get("username", "N/A")
                        first_name = last_update["message"]["from"].get("first_name", "N/A")

                        print(f"✅ ID encontrado: {user_id}")
                        print(f"👤 Usuario: {first_name} (@{username})")
                        print(f"📝 Configura ADMIN_USER_ID={user_id} en tu .env")

                        # Mostrar configuración completa
                        print(f"\n🔧 Configuración completa:")
                        print(f"ADMIN_USER_ID={user_id}")
                        print(f"READ_ONLY_MODE=true")
                        print(f"TELEGRAM_TOKEN={bot_token}")
                    else:
                        print("❌ No se encontraron mensajes recientes")
                else:
                    print("❌ No se pudieron obtener actualizaciones")
            else:
                print("❌ Error obteniendo actualizaciones")

        except Exception as e:
            print(f"❌ Error: {e}")

    else:
        print("❌ Opción inválida")

if __name__ == "__main__":
    main()
