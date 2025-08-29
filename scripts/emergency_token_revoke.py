#!/usr/bin/env python3
"""
🚨 SCRIPT DE EMERGENCIA - REVOCAR TOKEN EXPUESTO
Este script debe ejecutarse INMEDIATAMENTE si se detecta que un token ha sido expuesto.
"""

import requests
import json
import os
from dotenv import load_dotenv

def revoke_exposed_token():
    """Revocar token expuesto"""

    # ⚠️ TOKEN EXPUESTO - DEBE SER REVOCADO INMEDIATAMENTE
    # Cargar desde variable de entorno o archivo de configuración
    EXPOSED_TOKEN = os.getenv('EXPOSED_TOKEN', 'YOUR_EXPOSED_TOKEN_HERE')

    print("🚨 EMERGENCIA: TOKEN EXPUESTO DETECTADO")
    print("=" * 60)
    print(f"Token expuesto: {EXPOSED_TOKEN}")
    print("=" * 60)

    # Intentar revocar el token (Telegram no tiene endpoint directo para esto)
    # Pero podemos invalidarlo cambiando la configuración del bot

    try:
        # 1. Intentar obtener información del bot para confirmar que está activo
        response = requests.get(f"https://api.telegram.org/bot{EXPOSED_TOKEN}/getMe")

        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                print("❌ TOKEN AÚN ACTIVO - ACCIÓN REQUERIDA INMEDIATA")
                print("=" * 60)
                print("🔴 ACCIONES REQUERIDAS:")
                print("1. Ve a @BotFather en Telegram")
                print("2. Usa /mybots")
                print("3. Selecciona tu bot")
                print("4. Usa /revoke para revocar el token")
                print("5. Obtén un nuevo token")
                print("6. Actualiza todas las variables de entorno")
                print("=" * 60)

                # Mostrar información del bot comprometido
                bot_data = bot_info['result']
                print("🤖 INFORMACIÓN DEL BOT COMPROMETIDO:")
                print(f"   Nombre: {bot_data.get('first_name', 'N/A')}")
                print(f"   Username: @{bot_data.get('username', 'N/A')}")
                print(f"   Bot ID: {bot_data.get('id', 'N/A')}")
                print("=" * 60)

                return False
            else:
                print("✅ Token ya no es válido (posiblemente ya revocado)")
                return True
        else:
            print("✅ Token ya no es válido (posiblemente ya revocado)")
            return True

    except Exception as e:
        print(f"❌ Error verificando token: {e}")
        return False

def create_new_token_instructions():
    """Instrucciones para crear nuevo token"""
    print("\n🔄 INSTRUCCIONES PARA NUEVO TOKEN:")
    print("=" * 60)
    print("1. Ve a @BotFather en Telegram")
    print("2. Usa /newbot para crear un nuevo bot")
    print("3. O usa /mybots y selecciona tu bot existente")
    print("4. Usa /token para obtener un nuevo token")
    print("5. Actualiza TELEGRAM_BOT_TOKEN en tu .env")
    print("6. Actualiza GitHub Secrets si usas producción")
    print("=" * 60)

def update_env_template():
    """Crear template de .env actualizado"""
    env_template = """# C4A Alerts - Configuración Segura
# ⚠️ IMPORTANTE: NUNCA hardcodear tokens en el código

# Telegram Bot (NUEVO TOKEN SEGURO)
TELEGRAM_BOT_TOKEN=YOUR_NEW_SECURE_TOKEN_HERE

# Configuración de Usuario
ADMIN_USER_ID=YOUR_USER_ID_HERE
ADMIN_CHAT_ID=YOUR_CHAT_ID_HERE

# Configuración del Sistema
READ_ONLY_MODE=true
ENVIRONMENT=production

# Configuración JWT (se generan automáticamente)
DEMO_PASSWORD=YOUR_SECURE_PASSWORD_HERE

# Configuración de Base de Datos
DATABASE_URL=postgresql://user:password@localhost/c4a_alerts

# Configuración de Redis
REDIS_URL=redis://localhost:6379/0
"""

    with open(".env.template", "w") as f:
        f.write(env_template)

    print("✅ Template .env.template creado")
    print("   Copia este archivo a .env y configura tus valores")

def main():
    """Función principal de emergencia"""
    print("🚨 SCRIPT DE EMERGENCIA - REVOCACIÓN DE TOKEN")
    print("=" * 60)

    # Revocar token expuesto
    if revoke_exposed_token():
        print("✅ Token expuesto verificado como inválido")
    else:
        print("❌ TOKEN AÚN ACTIVO - ACCIÓN REQUERIDA")

    # Instrucciones para nuevo token
    create_new_token_instructions()

    # Crear template de configuración
    update_env_template()

    print("\n🔒 MEDIDAS DE SEGURIDAD ADICIONALES:")
    print("=" * 60)
    print("1. Revisa logs de acceso al bot")
    print("2. Monitorea actividad sospechosa")
    print("3. Considera cambiar todas las credenciales")
    print("4. Revisa el historial de Git por más tokens")
    print("5. Configura alertas de seguridad")
    print("=" * 60)

    print("🚨 EMERGENCIA: TOKEN EXPUESTO - ACCIÓN INMEDIATA REQUERIDA")

if __name__ == "__main__":
    main()
