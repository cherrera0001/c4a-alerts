"""
Manejador de comandos para el bot de Telegram
Gestiona las interacciones de usuarios con el bot
"""

import os
import json
import requests
from typing import Dict, Any, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class TelegramBotHandler:
    """Manejador de comandos del bot de Telegram"""

    def __init__(self):
        self.bot_token = os.getenv('TELEGRAM_TOKEN', '')
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"

    def handle_update(self, update_data: Dict[str, Any]) -> bool:
        """Manejar una actualización del bot"""
        try:
            if 'message' in update_data:
                return self._handle_message(update_data['message'])
            elif 'callback_query' in update_data:
                return self._handle_callback_query(update_data['callback_query'])
            return False
        except Exception as e:
            logger.error(f"Error manejando update: {e}")
            return False

    def _handle_message(self, message: Dict[str, Any]) -> bool:
        """Manejar un mensaje"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        text = message.get('text', '')

        # Extraer comando
        if text.startswith('/'):
            command = text.split()[0].lower()
            return self._handle_command(chat_id, user_id, command, text)
        else:
            # Mensaje normal
            return self._send_welcome_message(chat_id)

    def _handle_command(self, chat_id: int, user_id: int, command: str, full_text: str) -> bool:
        """Manejar un comando específico"""
        try:
            if command == '/start':
                return self._handle_start(chat_id, user_id)
            elif command == '/help':
                return self._handle_help(chat_id)
            elif command == '/status':
                return self._handle_status(chat_id)
            elif command == '/subscribe':
                return self._handle_subscribe(chat_id, user_id)
            elif command == '/unsubscribe':
                return self._handle_unsubscribe(chat_id, user_id)
            elif command == '/settings':
                return self._handle_settings(chat_id, user_id)
            elif command == '/about':
                return self._handle_about(chat_id)
            else:
                return self._send_unknown_command(chat_id, command)
        except Exception as e:
            logger.error(f"Error manejando comando {command}: {e}")
            return self._send_error_message(chat_id)

    def _handle_start(self, chat_id: int, user_id: int) -> bool:
        """Manejar comando /start"""
        welcome_message = f"""
🚀 <b>¡Bienvenido a C4A Alerts!</b>

🔒 <b>Plataforma de Threat Intelligence</b>

Te ayudamos a mantenerte informado sobre las últimas amenazas de seguridad cibernética.

✨ <b>Características principales:</b>
• Alertas en tiempo real de vulnerabilidades críticas
• Análisis de amenazas emergentes
• Monitoreo de fuentes de inteligencia
• Notificaciones personalizables

💡 <b>Comandos disponibles:</b>
/help - Ver ayuda completa
/status - Estado del sistema
/subscribe - Suscribirse a alertas
/settings - Configurar preferencias
/about - Información del proyecto

🔔 <b>Para comenzar:</b>
Usa /subscribe para activar las notificaciones de alertas de seguridad.

<i>Tu seguridad es nuestra prioridad.</i>
        """.strip()

        return self._send_message(chat_id, welcome_message)

    def _handle_help(self, chat_id: int) -> bool:
        """Manejar comando /help"""
        help_message = f"""
❓ <b>Ayuda - C4A Alerts</b>

📋 <b>Comandos disponibles:</b>

🚀 <b>/start</b> - Iniciar el bot y ver mensaje de bienvenida

❓ <b>/help</b> - Mostrar esta ayuda

📊 <b>/status</b> - Ver estado del sistema y alertas recientes

🔔 <b>/subscribe</b> - Suscribirse a alertas de seguridad
   Recibirás notificaciones sobre:
   • Nuevas vulnerabilidades críticas
   • Amenazas emergentes
   • Actualizaciones de seguridad

🔕 <b>/unsubscribe</b> - Cancelar suscripción a alertas

⚙️ <b>/settings</b> - Configurar preferencias de notificaciones
   • Frecuencia de alertas
   • Tipos de amenazas
   • Nivel de severidad

ℹ️ <b>/about</b> - Información sobre C4A Alerts

🔗 <b>Enlaces útiles:</b>
• Dashboard: https://your-domain.com
• Documentación: https://github.com/your-repo
• Soporte: @your_support_channel

<i>¿Necesitas ayuda adicional? Contacta a nuestro equipo de soporte.</i>
        """.strip()

        return self._send_message(chat_id, help_message)

    def _handle_status(self, chat_id: int) -> bool:
        """Manejar comando /status"""
        # Aquí puedes integrar con tu base de datos para obtener estadísticas reales
        status_message = f"""
📊 <b>Estado del Sistema - C4A Alerts</b>

🟢 <b>Estado:</b> Operativo
🕐 <b>Última actualización:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📈 <b>Estadísticas:</b>
• Alertas procesadas hoy: 47
• Amenazas críticas: 3
• Fuentes activas: 8
• Usuarios suscritos: 156

🔔 <b>Alertas recientes:</b>
• CVE-2024-XXXXX - Vulnerabilidad crítica en Apache
• Nuevo malware detectado: Ransomware XYZ
• Actualización de seguridad disponible

⚡ <b>Rendimiento:</b>
• Tiempo de respuesta: 2.3s
• Disponibilidad: 99.9%
• Última sincronización: 5 min

<i>El sistema está funcionando correctamente.</i>
        """.strip()

        return self._send_message(chat_id, status_message)

    def _handle_subscribe(self, chat_id: int, user_id: int) -> bool:
        """Manejar comando /subscribe"""
        # Aquí deberías guardar la suscripción en tu base de datos
        subscribe_message = f"""
🔔 <b>Suscripción Activada</b>

✅ <b>Estado:</b> Suscrito a alertas de seguridad

📋 <b>Recibirás notificaciones sobre:</b>
• 🔴 Vulnerabilidades críticas (CVSS 9.0-10.0)
• 🟠 Amenazas altas (CVSS 7.0-8.9)
• 🟡 Amenazas medias (CVSS 4.0-6.9)
• 🟢 Actualizaciones de seguridad

⚙️ <b>Configuración actual:</b>
• Frecuencia: En tiempo real
• Fuentes: Todas activas
• Formato: Resumido

💡 <b>Para personalizar:</b>
Usa /settings para ajustar tus preferencias

🔕 <b>Para cancelar:</b>
Usa /unsubscribe en cualquier momento

<i>¡Gracias por suscribirte! Te mantendremos informado.</i>
        """.strip()

        return self._send_message(chat_id, subscribe_message)

    def _handle_unsubscribe(self, chat_id: int, user_id: int) -> bool:
        """Manejar comando /unsubscribe"""
        # Aquí deberías eliminar la suscripción de tu base de datos
        unsubscribe_message = f"""
🔕 <b>Suscripción Cancelada</b>

❌ <b>Estado:</b> No suscrito a alertas

📝 <b>Ya no recibirás:</b>
• Notificaciones automáticas
• Alertas de seguridad
• Actualizaciones de amenazas

💡 <b>Para volver a suscribirte:</b>
Usa /subscribe en cualquier momento

🔔 <b>Para ver estado del sistema:</b>
Usa /status para ver información general

<i>Esperamos verte de vuelta pronto.</i>
        """.strip()

        return self._send_message(chat_id, unsubscribe_message)

    def _handle_settings(self, chat_id: int, user_id: int) -> bool:
        """Manejar comando /settings"""
        settings_message = f"""
⚙️ <b>Configuración - C4A Alerts</b>

🔧 <b>Configuración actual:</b>

🔔 <b>Notificaciones:</b>
• Estado: Activadas
• Frecuencia: En tiempo real
• Horario: 24/7

📊 <b>Niveles de severidad:</b>
• 🔴 Crítico (CVSS 9.0-10.0): ✅
• 🟠 Alto (CVSS 7.0-8.9): ✅
• 🟡 Medio (CVSS 4.0-6.9): ✅
• 🟢 Bajo (CVSS 0.1-3.9): ❌

🌐 <b>Fuentes de información:</b>
• CISA: ✅
• NVD: ✅
• MITRE: ✅
• VirusTotal: ✅
• AbuseIPDB: ✅

📱 <b>Formato de mensajes:</b>
• Resumido: ✅
• Detallado: ❌
• Con enlaces: ✅

💡 <b>Para cambiar configuración:</b>
Contacta a nuestro equipo de soporte.

<i>La configuración se aplica automáticamente.</i>
        """.strip()

        return self._send_message(chat_id, settings_message)

    def _handle_about(self, chat_id: int) -> bool:
        """Manejar comando /about"""
        about_message = f"""
ℹ️ <b>Acerca de C4A Alerts</b>

🔒 <b>Plataforma de Threat Intelligence</b>

C4A Alerts es una plataforma avanzada de inteligencia de amenazas cibernéticas diseñada para mantener informados a profesionales de seguridad, empresas y entusiastas sobre las últimas amenazas y vulnerabilidades.

🚀 <b>Características:</b>
• Monitoreo en tiempo real de múltiples fuentes
• Análisis automático de amenazas
• Notificaciones personalizables
• Dashboard interactivo
• API RESTful

🛡️ <b>Fuentes de información:</b>
• CISA (Cybersecurity & Infrastructure Security Agency)
• NVD (National Vulnerability Database)
• MITRE ATT&CK
• VirusTotal
• AbuseIPDB
• Y más...

👥 <b>Equipo:</b>
Desarrollado por profesionales de ciberseguridad para la comunidad.

🌐 <b>Enlaces:</b>
• GitHub: https://github.com/your-repo/c4a-alerts
• Documentación: https://docs.c4a-alerts.com
• Soporte: @your_support_channel

📄 <b>Licencia:</b>
MIT License - Código abierto

❤️ <b>Desarrollado con:</b>
• Python
• Next.js
• Telegram Bot API
• Firebase

<i>Gracias por usar C4A Alerts.</i>
        """.strip()

        return self._send_message(chat_id, about_message)

    def _send_welcome_message(self, chat_id: int) -> bool:
        """Enviar mensaje de bienvenida para mensajes normales"""
        welcome_message = f"""
👋 <b>¡Hola!</b>

Gracias por contactar con C4A Alerts.

💡 <b>Para comenzar:</b>
Usa /start para ver las opciones disponibles
Usa /help para ver todos los comandos

🔒 <b>Somos tu aliado en ciberseguridad.</b>
        """.strip()

        return self._send_message(chat_id, welcome_message)

    def _send_unknown_command(self, chat_id: int, command: str) -> bool:
        """Enviar mensaje para comando desconocido"""
        unknown_message = f"""
❓ <b>Comando no reconocido</b>

El comando <code>{command}</code> no existe.

💡 <b>Comandos disponibles:</b>
/start - Iniciar el bot
/help - Ver ayuda
/status - Estado del sistema
/subscribe - Suscribirse a alertas
/settings - Configurar preferencias
/about - Información del proyecto

<i>Usa /help para ver todos los comandos disponibles.</i>
        """.strip()

        return self._send_message(chat_id, unknown_message)

    def _send_error_message(self, chat_id: int) -> bool:
        """Enviar mensaje de error"""
        error_message = f"""
⚠️ <b>Error del Sistema</b>

Lo sentimos, ha ocurrido un error procesando tu solicitud.

🔄 <b>Por favor:</b>
• Intenta nuevamente en unos momentos
• Usa /help para ver comandos disponibles
• Contacta soporte si el problema persiste

<i>Estamos trabajando para resolver el problema.</i>
        """.strip()

        return self._send_message(chat_id, error_message)

    def _send_message(self, chat_id: int, text: str) -> bool:
        """Enviar mensaje a un chat específico"""
        try:
            payload = {
                'chat_id': chat_id,
                'text': text,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }

            response = requests.post(
                f"{self.base_url}/sendMessage",
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('ok'):
                    logger.info(f"Mensaje enviado a chat {chat_id}")
                    return True
                else:
                    logger.error(f"Error enviando mensaje: {result.get('description')}")
                    return False
            else:
                logger.error(f"Error HTTP {response.status_code}: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error enviando mensaje: {e}")
            return False

# Instancia global del manejador
bot_handler = TelegramBotHandler()
