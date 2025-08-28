"""
Webhook endpoint para el bot de Telegram
Recibe y procesa las actualizaciones del bot
"""

import functions_framework
import os
import json
import logging
from typing import Dict, Any

# Importar el manejador del bot
try:
    from notifiers.telegram_bot_handler import bot_handler
except ImportError:
    bot_handler = None
    logging.warning("Telegram bot handler no disponible")

logger = logging.getLogger(__name__)

@functions_framework.http
def telegram_webhook(request):
    """Webhook endpoint para el bot de Telegram"""

    # Configurar CORS
    if request.method == 'OPTIONS':
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600'
        }
        return ('', 204, headers)

    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    }

    try:
        # Verificar que es una solicitud POST
        if request.method != 'POST':
            return (json.dumps({
                'error': 'Method not allowed'
            }), 405, headers)

        # Obtener el cuerpo de la solicitud
        request_json = request.get_json(silent=True)

        if not request_json:
            logger.error("No se pudo parsear el JSON de la solicitud")
            return (json.dumps({
                'error': 'Invalid JSON'
            }), 400, headers)

        # Verificar que es una actualización válida de Telegram
        if 'update_id' not in request_json:
            logger.error("No se encontró update_id en la solicitud")
            return (json.dumps({
                'error': 'Invalid Telegram update'
            }), 400, headers)

        logger.info(f"Recibida actualización {request_json['update_id']}")

        # Procesar la actualización con el manejador del bot
        if bot_handler:
            success = bot_handler.handle_update(request_json)
            if success:
                logger.info(f"Actualización {request_json['update_id']} procesada exitosamente")
                return (json.dumps({
                    'status': 'success',
                    'update_id': request_json['update_id']
                }), 200, headers)
            else:
                logger.error(f"Error procesando actualización {request_json['update_id']}")
                return (json.dumps({
                    'error': 'Failed to process update'
                }), 500, headers)
        else:
            logger.error("Bot handler no disponible")
            return (json.dumps({
                'error': 'Bot handler not available'
            }), 500, headers)

    except Exception as e:
        logger.error(f"Error en webhook: {e}")
        return (json.dumps({
            'error': 'Internal server error'
        }), 500, headers)

def set_webhook():
    """Configurar el webhook para el bot"""
    import requests

    bot_token = os.getenv('TELEGRAM_TOKEN', '')
    if not bot_token:
        logger.error("TELEGRAM_TOKEN no configurado")
        return False

    # URL del webhook (ajusta según tu configuración)
    webhook_url = "https://your-function-url/telegram_webhook"

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/setWebhook",
            json={'url': webhook_url}
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                logger.info(f"Webhook configurado exitosamente: {webhook_url}")
                return True
            else:
                logger.error(f"Error configurando webhook: {result.get('description')}")
                return False
        else:
            logger.error(f"Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Error configurando webhook: {e}")
        return False

def delete_webhook():
    """Eliminar el webhook del bot"""
    import requests

    bot_token = os.getenv('TELEGRAM_TOKEN', '')
    if not bot_token:
        logger.error("TELEGRAM_TOKEN no configurado")
        return False

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/deleteWebhook"
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                logger.info("Webhook eliminado exitosamente")
                return True
            else:
                logger.error(f"Error eliminando webhook: {result.get('description')}")
                return False
        else:
            logger.error(f"Error HTTP {response.status_code}: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Error eliminando webhook: {e}")
        return False

def get_webhook_info():
    """Obtener información del webhook actual"""
    import requests

    bot_token = os.getenv('TELEGRAM_TOKEN', '')
    if not bot_token:
        logger.error("TELEGRAM_TOKEN no configurado")
        return None

    try:
        response = requests.get(
            f"https://api.telegram.org/bot{bot_token}/getWebhookInfo"
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                webhook_info = result['result']
                logger.info(f"Información del webhook: {webhook_info}")
                return webhook_info
            else:
                logger.error(f"Error obteniendo información del webhook: {result.get('description')}")
                return None
        else:
            logger.error(f"Error HTTP {response.status_code}: {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error obteniendo información del webhook: {e}")
        return None
