#!/usr/bin/env python3
"""
Script de prueba para verificar la configuración de Telegram
"""

import os
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

def test_telegram_config():
    """Probar la configuración de Telegram"""

    # Obtener variables de entorno
    bot_token = os.getenv('TELEGRAM_TOKEN', '')
    chat_id = os.getenv('CHAT_ID', '')

    print("🔍 Verificando configuración de Telegram...")
    print(f"Bot Token: {'✅ Configurado' if bot_token else '❌ No configurado'}")
    print(f"Chat ID: {'✅ Configurado' if chat_id else '❌ No configurado'}")

    if not bot_token or not chat_id:
        print("❌ Telegram no está configurado correctamente")
        return False

    # Construir URL de la API
    base_url = f"https://api.telegram.org/bot{bot_token}"

    # 1. Verificar que el bot existe
    try:
        response = requests.get(f"{base_url}/getMe", timeout=10)
        if response.status_code == 200:
            bot_info = response.json()
            print(f"✅ Bot verificado: @{bot_info['result']['username']}")
        else:
            print(f"❌ Error verificando bot: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error conectando a Telegram: {e}")
        return False

    # 2. Enviar mensaje de prueba
    test_message = f"""
🔧 <b>Prueba de Configuración - C4A Alerts</b>

✅ <b>Estado:</b> Configuración verificada
🕐 <b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🔗 <b>Plataforma:</b> C4A Alerts - Threat Intelligence

<i>Este es un mensaje de prueba para verificar que la integración con Telegram funciona correctamente.</i>
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
            print("✅ Mensaje de prueba enviado exitosamente")
            print(f"📱 Mensaje ID: {result['result']['message_id']}")
            return True
        else:
            print(f"❌ Error enviando mensaje: {response.status_code}")
            print(f"Respuesta: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error enviando mensaje: {e}")
        return False

def test_alert_format():
    """Probar el formato de alerta"""

    test_alert = {
        'title': '🚨 Alerta de Prueba - C4A Alerts',
        'description': 'Esta es una alerta de prueba para verificar el formato de mensajes en Telegram',
        'severity': 'high',
        'source': 'test-system',
        'iocs': [
            {'type': 'ip', 'value': '192.168.1.100'},
            {'type': 'domain', 'value': 'test-malicious.com'},
            {'type': 'url', 'value': 'https://test-malicious.com/payload'}
        ],
        'tags': ['test', 'telegram', 'verification'],
        'cvss_score': 8.5,
        'cve_id': 'CVE-2024-TEST-001',
        'threat_actor': 'Test Group',
        'published_at': datetime.now().isoformat()
    }

    print("\n🎯 Probando formato de alerta...")

    # Simular el formato del notificador
    title = test_alert.get('title', 'Sin título')
    description = test_alert.get('description', 'Sin descripción')
    severity = test_alert.get('severity', 'unknown')
    source = test_alert.get('source', 'unknown')

    # Emojis por severidad
    severity_emoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    }

    emoji = severity_emoji.get(severity, '⚪')

    # Formatear IOCs
    iocs_text = ""
    if test_alert.get('iocs'):
        ioc_lines = []
        for ioc in test_alert['iocs']:
            ioc_type = ioc.get('type', 'unknown')
            ioc_value = ioc.get('value', 'unknown')
            ioc_lines.append(f"• <code>{ioc_type}: {ioc_value}</code>")
        iocs_text = "\n".join(ioc_lines)

    # Formatear tags
    tags_text = ""
    if test_alert.get('tags'):
        tags = [f"#{tag.replace(' ', '_')}" for tag in test_alert['tags']]
        tags_text = " ".join(tags)

    message = f"""
{emoji} <b>🚨 ALERTA DE SEGURIDAD</b>

<b>📋 Título:</b> {title}
<b>📝 Descripción:</b> {description}
<b>⚠️ Severidad:</b> {severity.upper()}
<b>🔗 Fuente:</b> {source}

"""

    if iocs_text:
        message += f"<b>🎯 IOCs:</b>\n{iocs_text}\n\n"

    if tags_text:
        message += f"<b>🏷️ Tags:</b> {tags_text}\n\n"

    # Agregar metadata adicional
    if test_alert.get('cvss_score'):
        message += f"<b>📊 CVSS:</b> {test_alert['cvss_score']}\n"

    if test_alert.get('cve_id'):
        message += f"<b>🔍 CVE:</b> {test_alert['cve_id']}\n"

    if test_alert.get('threat_actor'):
        message += f"<b>👤 Actor:</b> {test_alert['threat_actor']}\n"

    message += f"\n<b>🕐 Timestamp:</b> {test_alert.get('published_at', 'N/A')}"
    message += f"\n\n<b>🔗 Plataforma:</b> C4A Alerts - Threat Intelligence"

    print("✅ Formato de alerta generado correctamente")
    print("📝 Vista previa del mensaje:")
    print("-" * 50)
    print(message)
    print("-" * 50)

    return message

if __name__ == "__main__":
    print("🚀 Iniciando pruebas de Telegram...")
    print("=" * 50)

    # Probar configuración
    if test_telegram_config():
        print("\n✅ Configuración de Telegram verificada")

        # Probar formato
        test_alert_format()

        print("\n🎉 ¡Telegram está listo para recibir alertas!")
        print("📱 Las alertas se enviarán automáticamente cuando lleguen")
    else:
        print("\n❌ Problemas con la configuración de Telegram")
        print("🔧 Verifica las variables de entorno:")
        print("   - TELEGRAM_TOKEN")
        print("   - CHAT_ID")
