#!/usr/bin/env python3
"""
Script para configurar el webhook del bot de Telegram
Permite que el bot reciba comandos desde la web
"""

import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def setup_webhook():
    """Configurar webhook para el bot"""
    token = os.getenv('TELEGRAM_TOKEN', '')

    if not token:
        print("❌ TELEGRAM_TOKEN no está configurado")
        return False

    # URL del webhook (debe ser HTTPS)
    webhook_url = input("🌐 Ingresa la URL de tu webhook (HTTPS): ").strip()

    if not webhook_url.startswith('https://'):
        print("❌ La URL debe ser HTTPS")
        return False

    # Agregar el endpoint del webhook
    if not webhook_url.endswith('/telegram-webhook'):
        webhook_url = webhook_url.rstrip('/') + '/telegram-webhook'

    print(f"🔗 Configurando webhook: {webhook_url}")

    try:
        # Configurar webhook
        response = requests.post(
            f"https://api.telegram.org/bot{token}/setWebhook",
            json={'url': webhook_url}
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Webhook configurado exitosamente")
                print(f"🔗 URL: {webhook_url}")
                return True
            else:
                print(f"❌ Error: {result.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error configurando webhook: {e}")
        return False

def get_webhook_info():
    """Obtener información del webhook actual"""
    token = os.getenv('TELEGRAM_TOKEN', '')

    if not token:
        print("❌ TELEGRAM_TOKEN no está configurado")
        return False

    try:
        response = requests.get(f"https://api.telegram.org/bot{token}/getWebhookInfo")

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                webhook_info = result['result']

                print("📊 INFORMACIÓN DEL WEBHOOK:")
                print("=" * 40)
                print(f"🔗 URL: {webhook_info.get('url', 'No configurado')}")
                print(f"✅ Activo: {webhook_info.get('ok', False)}")
                print(f"📊 Errores: {webhook_info.get('last_error_date', 'N/A')}")
                print(f"📝 Mensaje: {webhook_info.get('last_error_message', 'N/A')}")
                print(f"📈 Actualizaciones: {webhook_info.get('pending_update_count', 0)}")

                return True
            else:
                print(f"❌ Error: {result.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error obteniendo información: {e}")
        return False

def delete_webhook():
    """Eliminar webhook"""
    token = os.getenv('TELEGRAM_TOKEN', '')

    if not token:
        print("❌ TELEGRAM_TOKEN no está configurado")
        return False

    try:
        response = requests.post(f"https://api.telegram.org/bot{token}/deleteWebhook")

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Webhook eliminado exitosamente")
                return True
            else:
                print(f"❌ Error: {result.get('description', 'Unknown error')}")
                return False
        else:
            print(f"❌ Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error eliminando webhook: {e}")
        return False

def test_bot_commands():
    """Probar comandos del bot"""
    print("\n🤖 PROBANDO COMANDOS DEL BOT:")
    print("=" * 40)
    print("1. Ve a https://t.me/C4A_news_bot")
    print("2. Haz clic en 'START BOT'")
    print("3. Envía /start")
    print("4. Prueba otros comandos:")
    print("   - /help - Ver ayuda")
    print("   - /status - Ver estado")
    print("   - /subscribe - Suscribirse")
    print("   - /settings - Configuración")
    print("   - /about - Información del bot")

def main():
    """Función principal"""
    print("=" * 60)
    print("🔧 CONFIGURADOR DE WEBHOOK DE TELEGRAM")
    print("=" * 60)

    while True:
        print("\n📋 OPCIONES:")
        print("1. Configurar webhook")
        print("2. Ver información del webhook")
        print("3. Eliminar webhook")
        print("4. Probar comandos del bot")
        print("5. Salir")

        choice = input("\n🔢 Selecciona una opción (1-5): ").strip()

        if choice == '1':
            setup_webhook()
        elif choice == '2':
            get_webhook_info()
        elif choice == '3':
            delete_webhook()
        elif choice == '4':
            test_bot_commands()
        elif choice == '5':
            print("👋 ¡Hasta luego!")
            break
        else:
            print("❌ Opción inválida")

if __name__ == "__main__":
    main()
