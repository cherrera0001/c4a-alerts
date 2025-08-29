#!/usr/bin/env python3
"""
Script simple para probar Telegram con la API desplegada
"""

import requests
import json
from datetime import datetime

def test_telegram_via_api():
    """Probar Telegram a través de la API desplegada"""

    api_url = "https://us-central1-c4a-alerts-personal-1756352164.cloudfunctions.net/c4a-alerts-api/process_alert"

    # Crear alerta de prueba única
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    test_alert = {
        "alert_data": {
            "title": f"🔧 Test Telegram - {timestamp}",
            "description": f"Esta es una prueba de Telegram desde la API desplegada - {timestamp}",
            "severity": "high",
            "source": "telegram-test-api",
            "iocs": [
                {"type": "ip", "value": "192.168.1.200"},
                {"type": "domain", "value": "test-telegram.com"}
            ],
            "tags": ["telegram", "test", "api", "verification"],
            "cvss_score": 7.5,
            "cve_id": "CVE-2024-TELEGRAM-TEST",
            "threat_actor": "Test Group",
            "published_at": datetime.now().isoformat()
        }
    }

    print("🚀 Enviando alerta de prueba a la API...")
    print(f"📡 URL: {api_url}")
    print(f"📝 Alerta: {test_alert['alert_data']['title']}")

    try:
        response = requests.post(
            api_url,
            headers={"Content-Type": "application/json"},
            json=test_alert,
            timeout=30
        )

        print(f"📊 Status Code: {response.status_code}")
        print(f"📄 Response: {response.text}")

        if response.status_code == 200:
            result = response.json()
            print("✅ Alerta procesada exitosamente")

            # Verificar si Telegram está configurado
            if 'notifications' in result:
                telegram_status = result['notifications'].get('telegram', {})
                print(f"📱 Telegram Status: {telegram_status}")

                if telegram_status.get('configured', False):
                    if telegram_status.get('status') == 'success':
                        print("✅ Telegram enviado exitosamente")
                    else:
                        print(f"❌ Error en Telegram: {telegram_status.get('error', 'Unknown error')}")
                else:
                    print("❌ Telegram no está configurado")
            else:
                print("⚠️ No se encontró información de notificaciones")

        else:
            print(f"❌ Error en la API: {response.status_code}")

    except Exception as e:
        print(f"❌ Error de conexión: {e}")

def test_telegram_direct():
    """Probar Telegram directamente (solo si tienes las variables locales)"""

    import os

    bot_token = os.getenv('TELEGRAM_TOKEN', '')
    chat_id = os.getenv('CHAT_ID', '')

    if not bot_token or not chat_id:
        print("❌ Variables de Telegram no configuradas localmente")
        print("🔧 Las variables están en GitHub Secrets")
        return

    print("🔧 Probando Telegram directamente...")

    base_url = f"https://api.telegram.org/bot{bot_token}"

    test_message = f"""
🔧 <b>Prueba Directa - C4A Alerts</b>

✅ <b>Estado:</b> Prueba directa desde script local
🕐 <b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🔗 <b>Plataforma:</b> C4A Alerts - Threat Intelligence

<i>Esta es una prueba directa para verificar la configuración de Telegram.</i>
"""

    payload = {
        'chat_id': chat_id,
        'text': test_message,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True
    }

    try:
        response = requests.post(
            f"{base_url}/sendMessage",
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            print("✅ Mensaje enviado directamente a Telegram")
            print(f"📱 Mensaje ID: {result['result']['message_id']}")
        else:
            print(f"❌ Error enviando mensaje: {response.status_code}")
            print(f"Respuesta: {response.text}")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("🚀 Iniciando pruebas de Telegram...")
    print("=" * 50)

    # Probar a través de la API
    test_telegram_via_api()

    print("\n" + "=" * 50)

    # Probar directamente (solo si tienes variables locales)
    test_telegram_direct()

    print("\n🎯 Verifica tu Telegram para ver si llegaron los mensajes")
    print("📱 Si no llegaron, revisa:")
    print("   1. Que el bot esté agregado al chat/canal")
    print("   2. Que el bot tenga permisos para enviar mensajes")
    print("   3. Que el CHAT_ID sea correcto")
