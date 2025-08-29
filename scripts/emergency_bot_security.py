#!/usr/bin/env python3
"""
SCRIPT DE EMERGENCIA - SEGURIDAD DEL BOT
Ejecutar INMEDIATAMENTE para proteger el bot
"""

import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def emergency_bot_security():
    """Acciones de emergencia para proteger el bot"""

    token = os.getenv('TELEGRAM_TOKEN', '')

    if not token:
        print("❌ ERROR: TELEGRAM_TOKEN no encontrado")
        return False

    print("🚨 EMERGENCIA DE SEGURIDAD - BOT COMPROMETIDO")
    print("=" * 60)

    # 1. ELIMINAR WEBHOOK (CRÍTICO)
    print("🔒 1. Eliminando webhook...")
    try:
        response = requests.post(f"https://api.telegram.org/bot{token}/deleteWebhook")
        if response.status_code == 200:
            print("✅ Webhook eliminado")
        else:
            print(f"❌ Error eliminando webhook: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

    # 2. DESACTIVAR BOT TEMPORALMENTE
    print("🔒 2. Desactivando bot...")
    try:
        # Cambiar descripción para indicar mantenimiento
        response = requests.post(
            f"https://api.telegram.org/bot{token}/setMyDescription",
            json={'description': '🔒 BOT EN MANTENIMIENTO - NO DISPONIBLE'}
        )
        if response.status_code == 200:
            print("✅ Bot marcado como en mantenimiento")
        else:
            print(f"❌ Error: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

    # 3. LIMPIAR COMANDOS
    print("🔒 3. Limpiando comandos...")
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/setMyCommands",
            json={'commands': []}
        )
        if response.status_code == 200:
            print("✅ Comandos eliminados")
        else:
            print(f"❌ Error: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

    # 4. VERIFICAR ESTADO
    print("🔒 4. Verificando estado...")
    try:
        response = requests.get(f"https://api.telegram.org/bot{token}/getMe")
        if response.status_code == 200:
            bot_info = response.json()['result']
            print(f"✅ Bot: @{bot_info['username']}")
            print(f"✅ Nombre: {bot_info['first_name']}")
            print(f"✅ Activo: {bot_info.get('can_join_groups', False)}")
        else:
            print(f"❌ Error verificando bot: {response.status_code}")
    except Exception as e:
        print(f"❌ Error: {e}")

    return True

def generate_new_token_instructions():
    """Instrucciones para generar nuevo token"""
    print("\n" + "=" * 60)
    print("🆕 INSTRUCCIONES PARA NUEVO TOKEN")
    print("=" * 60)
    print("1. Ve a @BotFather en Telegram")
    print("2. Envía /mybots")
    print("3. Selecciona @C4A_news_bot")
    print("4. Ve a 'Bot Settings' > 'API Token'")
    print("5. Haz clic en 'Revoke current token'")
    print("6. Genera un nuevo token")
    print("7. Actualiza tu archivo .env")
    print("8. NUNCA subas el token a GitHub")
    print()

def security_recommendations():
    """Recomendaciones de seguridad"""
    print("🔒 RECOMENDACIONES DE SEGURIDAD:")
    print("=" * 40)
    print("✅ Usar variables de entorno (.env)")
    print("✅ .env en .gitignore")
    print("✅ GitHub Secrets para producción")
    print("✅ Validación de entrada")
    print("✅ Filtros de contenido")
    print("✅ Autenticación de usuarios")
    print("✅ Rate limiting")
    print("✅ Logs de seguridad")
    print("✅ Monitoreo de actividad")
    print()

def main():
    """Función principal"""
    print("🚨 SCRIPT DE EMERGENCIA - SEGURIDAD DEL BOT")
    print("=" * 60)

    # Ejecutar acciones de emergencia
    if emergency_bot_security():
        print("\n✅ Acciones de emergencia completadas")
    else:
        print("\n❌ Error en acciones de emergencia")

    # Mostrar instrucciones
    generate_new_token_instructions()
    security_recommendations()

    print("🚨 ACCIÓN REQUERIDA:")
    print("1. Revoca el token actual INMEDIATAMENTE")
    print("2. Genera un nuevo token")
    print("3. Actualiza tu configuración")
    print("4. Revisa todos los repositorios por tokens expuestos")
    print("5. Implementa validación de entrada")
    print()

if __name__ == "__main__":
    main()
