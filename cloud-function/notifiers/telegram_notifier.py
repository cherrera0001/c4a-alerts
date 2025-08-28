"""
Telegram Notifier for C4A Alerts
Envía alertas a canales de Telegram
"""

import os
import json
import requests
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class TelegramNotifier:
    """Notificador para enviar alertas a Telegram"""

    def __init__(self):
        self.bot_token = os.getenv('TELEGRAM_TOKEN', '')  # Usar el nombre correcto del secret
        self.chat_id = os.getenv('CHAT_ID', '')  # Usar el nombre correcto del secret
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"

    def is_configured(self) -> bool:
        """Verificar si Telegram está configurado"""
        return bool(self.bot_token and self.chat_id)

    def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Enviar alerta a Telegram"""
        if not self.is_configured():
            logger.warning("Telegram no está configurado")
            return False

        try:
            message = self._format_alert_message(alert_data)

            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }

            response = requests.post(
                f"{self.base_url}/sendMessage",
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                logger.info(f"Alerta enviada a Telegram: {alert_data.get('title', 'Unknown')}")
                return True
            else:
                logger.error(f"Error enviando a Telegram: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error en notificador Telegram: {e}")
            return False

    def _format_alert_message(self, alert_data: Dict[str, Any]) -> str:
        """Formatear mensaje de alerta para Telegram"""
        title = alert_data.get('title', 'Sin título')
        description = alert_data.get('description', 'Sin descripción')
        severity = alert_data.get('severity', 'unknown')
        source = alert_data.get('source', 'unknown')

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
        if alert_data.get('iocs'):
            ioc_lines = []
            for ioc in alert_data['iocs']:
                ioc_type = ioc.get('type', 'unknown')
                ioc_value = ioc.get('value', 'unknown')
                ioc_lines.append(f"• <code>{ioc_type}: {ioc_value}</code>")
            iocs_text = "\n".join(ioc_lines)

        # Formatear tags
        tags_text = ""
        if alert_data.get('tags'):
            tags = [f"#{tag.replace(' ', '_')}" for tag in alert_data['tags']]
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
        if alert_data.get('cvss_score'):
            message += f"<b>📊 CVSS:</b> {alert_data['cvss_score']}\n"

        if alert_data.get('cve_id'):
            message += f"<b>🔍 CVE:</b> {alert_data['cve_id']}\n"

        if alert_data.get('threat_actor'):
            message += f"<b>👤 Actor:</b> {alert_data['threat_actor']}\n"

        message += f"\n<b>🕐 Timestamp:</b> {alert_data.get('published_at', 'N/A')}"
        message += f"\n\n<b>🔗 Plataforma:</b> C4A Alerts - Threat Intelligence"

        return message.strip()

# Instancia global del notificador
telegram_notifier = TelegramNotifier()
