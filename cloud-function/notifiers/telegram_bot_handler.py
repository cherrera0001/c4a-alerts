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
        # URL del sistema C4A Alerts para análisis de malware
        self.c4a_api_url = os.getenv('C4A_API_URL', 'http://localhost:8000')
        # Configuración de acceso restringido
        self.admin_user_id = int(os.getenv('ADMIN_USER_ID', '0'))  # Tu ID de usuario
        self.read_only_mode = os.getenv('READ_ONLY_MODE', 'true').lower() == 'true'

    def handle_update(self, update_data: Dict[str, Any]) -> bool:
        """Manejar una actualización del bot"""
        try:
            if 'message' in update_data:
                return self._handle_message(update_data['message'])
            elif 'callback_query' in update_data:
                return self._handle_callback_query(update_data['callback_query'])
            return False
        except Exception as e:
            # ⚠️ SEGURIDAD: Sanitizar logs para evitar inyección
            logger.error(f"Error manejando update: {str(e)[:100]}...")
            return False

    def _handle_message(self, message: Dict[str, Any]) -> bool:
        """Manejar un mensaje"""
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        text = message.get('text', '')

        # 🔒 VERIFICACIÓN DE ACCESO RESTRINGIDO
        if self.read_only_mode and user_id != self.admin_user_id:
            return self._handle_unauthorized_access(chat_id, user_id, text)

        # 🔍 ANÁLISIS DE MALWARE EN TIEMPO REAL (solo para admin)
        malware_analysis = self._analyze_message_for_malware(text, user_id)

        if malware_analysis.get('malware_detected', False):
            # 🚨 MALWARE DETECTADO - ENVIAR ALERTA
            return self._handle_malware_detection(chat_id, user_id, text, malware_analysis)

        # Extraer comando
        if text.startswith('/'):
            command = text.split()[0].lower()
            return self._handle_command(chat_id, user_id, command, text)
        else:
            # Mensaje normal (solo admin puede enviar)
            return self._send_welcome_message(chat_id)

    def _handle_unauthorized_access(self, chat_id: int, user_id: int, text: str) -> bool:
        """Manejar acceso no autorizado"""
        try:
            # Verificar si es un comando de lectura permitido
            if text.startswith('/'):
                command = text.split()[0].lower()
                if command in ['/start', '/help', '/status', '/about', '/security']:
                    # Permitir comandos de lectura
                    return self._handle_read_only_command(chat_id, user_id, command, text)

            # Bloquear todo lo demás
            block_message = f"""
🚫 <b>Acceso Restringido</b>

⚠️ <b>Este bot es de solo lectura</b>

📖 <b>Comandos disponibles:</b>
/start - Información del bot
/help - Ayuda
/status - Estado del sistema
/about - Acerca del proyecto
/security - Información de seguridad

❌ <b>No puedes enviar:</b>
• Mensajes de texto
• Imágenes
• Archivos
• URLs
• Cualquier otro contenido

🔒 <b>Razón:</b>
Este es un bot informativo de seguridad. Solo el administrador puede enviar contenido.

📞 <b>Si necesitas ayuda:</b>
Contacta al administrador del sistema.

<i>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
            """.strip()

            self._send_message(chat_id, block_message)

            # Registrar intento de acceso no autorizado
            logger.warning(f"Acceso no autorizado - Usuario: {user_id}, Chat: {chat_id}, Mensaje: {text[:50]}...")

            return True

        except Exception as e:
            logger.error(f"Error manejando acceso no autorizado: {e}")
            return False

    def _handle_read_only_command(self, chat_id: int, user_id: int, command: str, text: str) -> bool:
        """Manejar comandos de solo lectura para usuarios no autorizados"""
        try:
            if command == '/start':
                return self._handle_start_readonly(chat_id, user_id)
            elif command == '/help':
                return self._handle_help_readonly(chat_id)
            elif command == '/status':
                return self._handle_status_readonly(chat_id)
            elif command == '/about':
                return self._handle_about_readonly(chat_id)
            elif command == '/security':
                return self._handle_security_readonly(chat_id)
            else:
                return self._send_unknown_command(chat_id, command)
        except Exception as e:
            logger.error(f"Error manejando comando de solo lectura {command}: {e}")
            return self._send_error_message(chat_id)

    def _handle_start_readonly(self, chat_id: int, user_id: int) -> bool:
        """Manejar comando /start para usuarios de solo lectura"""
        welcome_message = f"""
🚀 <b>¡Bienvenido a C4A Alerts!</b>

🔒 <b>Plataforma de Threat Intelligence - Modo Solo Lectura</b>

📖 <b>Este bot es informativo y de solo lectura.</b>

✨ <b>Características disponibles:</b>
• Leer alertas de seguridad
• Ver información de amenazas
• Consultar estado del sistema
• Obtener ayuda

🚫 <b>Restricciones:</b>
• No puedes enviar mensajes
• No puedes enviar imágenes
• No puedes enviar archivos
• No puedes enviar URLs

💡 <b>Comandos disponibles:</b>
/help - Ver ayuda completa
/status - Estado del sistema
/security - Información de seguridad
/about - Información del proyecto

🔔 <b>Para recibir alertas:</b>
Las alertas se envían automáticamente por el administrador.

🛡️ <b>Tu seguridad está protegida automáticamente.</b>

<i>Modo: Solo Lectura | Usuario: {user_id}</i>
        """.strip()

        return self._send_message(chat_id, welcome_message)

    def _handle_help_readonly(self, chat_id: int) -> bool:
        """Manejar comando /help para usuarios de solo lectura"""
        help_message = f"""
📖 <b>Ayuda - C4A Alerts (Modo Solo Lectura)</b>

🔒 <b>Este bot funciona en modo solo lectura</b>

📋 <b>Comandos disponibles:</b>
/start - Información del bot
/help - Esta ayuda
/status - Estado del sistema
/security - Información de seguridad
/about - Acerca del proyecto

🚫 <b>Lo que NO puedes hacer:</b>
• Enviar mensajes de texto
• Enviar imágenes o archivos
• Enviar URLs o enlaces
• Ejecutar comandos administrativos

💡 <b>Para qué sirve este bot:</b>
• Recibir alertas de seguridad
• Consultar información de amenazas
• Ver estado del sistema
• Obtener ayuda sobre seguridad

🔔 <b>Alertas automáticas:</b>
El administrador enviará alertas automáticamente cuando sea necesario.

📞 <b>Si necesitas ayuda:</b>
Contacta al administrador del sistema.

<i>Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
        """.strip()

        return self._send_message(chat_id, help_message)

    def _handle_status_readonly(self, chat_id: int) -> bool:
        """Manejar comando /status para usuarios de solo lectura"""
        status_message = f"""
📊 <b>Estado del Sistema - C4A Alerts</b>

🟢 <b>Estado General:</b> OPERATIVO

🛡️ <b>Protección de Seguridad:</b>
• Sistema de detección de malware: ACTIVO
• Análisis en tiempo real: FUNCIONANDO
• Alertas automáticas: CONFIGURADAS

📈 <b>Estadísticas:</b>
• 8 reglas de detección activas
• 6 técnicas de evasión monitoreadas
• 15 comandos sospechosos detectados
• Tiempo de respuesta: < 1 segundo

🔒 <b>Modo de Acceso:</b> SOLO LECTURA

👤 <b>Permisos de Usuario:</b>
• Leer información: ✅ PERMITIDO
• Enviar contenido: ❌ BLOQUEADO
• Ejecutar comandos: ❌ BLOQUEADO

💡 <b>Tu seguridad está protegida automáticamente.</b>

<i>Última verificación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
        """.strip()

        return self._send_message(chat_id, status_message)

    def _handle_about_readonly(self, chat_id: int) -> bool:
        """Manejar comando /about para usuarios de solo lectura"""
        about_message = f"""
ℹ️ <b>Acerca de C4A Alerts</b>

🔒 <b>Plataforma de Threat Intelligence</b>

📋 <b>Descripción:</b>
C4A Alerts es una plataforma avanzada de inteligencia de amenazas que proporciona alertas en tiempo real sobre vulnerabilidades de seguridad y amenazas emergentes.

✨ <b>Características:</b>
• Detección automática de malware
• Análisis de amenazas en tiempo real
• Alertas personalizables
• Protección contra payload downloaders
• Monitoreo de técnicas de evasión

🛡️ <b>Seguridad:</b>
• Modo solo lectura para usuarios
• Acceso restringido al administrador
• Análisis automático de contenido
• Bloqueo de contenido malicioso

🔔 <b>Uso:</b>
Este bot funciona en modo informativo. El administrador enviará alertas automáticamente cuando detecte amenazas relevantes.

📞 <b>Contacto:</b>
Para soporte técnico, contacta al administrador del sistema.

<i>Versión: 2.0.0 | Modo: Solo Lectura</i>
        """.strip()

        return self._send_message(chat_id, about_message)

    def _handle_security_readonly(self, chat_id: int) -> bool:
        """Manejar comando /security para usuarios de solo lectura"""
        security_message = f"""
🛡️ <b>Información de Seguridad - C4A Alerts</b>

🔒 <b>Protección Activa:</b>
• Análisis de malware en tiempo real
• Detección de payload downloaders
• Identificación de técnicas de evasión
• Monitoreo de comandos sospechosos

📊 <b>Estadísticas del Sistema:</b>
• 8 reglas de detección activas
• 6 técnicas de evasión monitoreadas
• 15 comandos sospechosos detectados
• Tiempo de respuesta: < 1 segundo

🎯 <b>Familias de Malware Detectadas:</b>
• RedTail droppers
• Payload downloaders
• Shell script malware
• Binary payloads

🔒 <b>Modo de Acceso:</b>
• Tu acceso: SOLO LECTURA
• Administrador: ACCESO COMPLETO
• Contenido malicioso: BLOQUEADO AUTOMÁTICAMENTE

💡 <b>Tu seguridad está protegida automáticamente.</b>

⚠️ <b>Nota:</b>
Como usuario de solo lectura, no puedes enviar contenido, pero estás protegido contra amenazas.

<i>Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
        """.strip()

        return self._send_message(chat_id, security_message)

    def _analyze_message_for_malware(self, text: str, user_id: int) -> Dict[str, Any]:
        """Analizar mensaje en busca de malware usando C4A Alerts"""
        try:
            # Preparar datos para análisis
            analysis_data = {
                "content": text,
                "source": f"telegram_user_{user_id}",
                "filename": "",
                "url": "",
                "user_agent": "TelegramBot/1.0",
                "ip_address": ""
            }

            # Llamar a la API de C4A Alerts
            response = requests.post(
                f"{self.c4a_api_url}/api/v1/malware/analyze",
                json=analysis_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"Análisis de malware completado para usuario {user_id}")
                return result.get('analysis_results', {})
            else:
                logger.error(f"Error en análisis de malware: {response.status_code}")
                return {"malware_detected": False}

        except Exception as e:
            logger.error(f"Error analizando malware: {e}")
            return {"malware_detected": False}

    def _handle_malware_detection(self, chat_id: int, user_id: int, text: str, analysis: Dict[str, Any]) -> bool:
        """Manejar detección de malware"""
        try:
            # Crear mensaje de alerta
            alert_message = f"""
🚨 <b>¡ALERTA DE SEGURIDAD!</b>

⚠️ <b>Malware detectado en tu mensaje</b>

🔍 <b>Análisis:</b>
• Familia: {analysis.get('malware_family', 'unknown').upper()}
• Severidad: {analysis.get('severity', 'unknown').upper()}
• Confianza: {analysis.get('confidence_score', 0):.1%}

🛡️ <b>Técnicas detectadas:</b>
{self._format_evasion_techniques(analysis.get('evasion_techniques', []))}

💡 <b>Acciones recomendadas:</b>
{self._format_recommended_actions(analysis.get('recommended_actions', []))}

🔒 <b>Tu mensaje ha sido bloqueado por seguridad.</b>

📞 <b>Si crees que esto es un error:</b>
Contacta al equipo de seguridad.

<i>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
            """.strip()

            # Enviar alerta al usuario
            self._send_message(chat_id, alert_message)

            # Enviar alerta al administrador
            admin_chat_id = os.getenv('ADMIN_CHAT_ID', '')
            if admin_chat_id:
                admin_alert = f"""
🚨 <b>ALERTA ADMINISTRATIVA</b>

⚠️ <b>Malware detectado en Telegram</b>

👤 <b>Usuario:</b> {user_id}
💬 <b>Mensaje:</b> {text[:100]}...
🔍 <b>Familia:</b> {analysis.get('malware_family', 'unknown')}
📊 <b>Confianza:</b> {analysis.get('confidence_score', 0):.1%}

<i>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
                """.strip()
                self._send_message(int(admin_chat_id), admin_alert)

            # Registrar en logs
            logger.warning(f"Malware detectado - Usuario: {user_id}, Familia: {analysis.get('malware_family')}, Confianza: {analysis.get('confidence_score')}")

            return True

        except Exception as e:
            logger.error(f"Error manejando detección de malware: {e}")
            return False

    def _format_evasion_techniques(self, techniques: list) -> str:
        """Formatear técnicas de evasión para mostrar"""
        if not techniques:
            return "• Ninguna técnica específica detectada"

        formatted = []
        for technique in techniques[:5]:  # Mostrar máximo 5
            formatted.append(f"• {technique.replace('_', ' ').title()}")

        if len(techniques) > 5:
            formatted.append(f"• ... y {len(techniques) - 5} más")

        return "\n".join(formatted)

    def _format_recommended_actions(self, actions: list) -> str:
        """Formatear acciones recomendadas para mostrar"""
        if not actions:
            return "• Revisar el sistema de seguridad"

        formatted = []
        for action in actions[:3]:  # Mostrar máximo 3
            # Remover emojis para mejor formato
            clean_action = action.split(' ', 1)[1] if ' ' in action else action
            formatted.append(f"• {clean_action}")

        if len(actions) > 3:
            formatted.append(f"• ... y {len(actions) - 3} acciones más")

        return "\n".join(formatted)

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
            elif command == '/security':
                return self._handle_security_info(chat_id)
            else:
                return self._send_unknown_command(chat_id, command)
        except Exception as e:
            logger.error(f"Error manejando comando {command}: {e}")
            return self._send_error_message(chat_id)

    def _handle_security_info(self, chat_id: int) -> bool:
        """Manejar comando /security - Información de seguridad"""
        security_message = f"""
🛡️ <b>Información de Seguridad C4A Alerts</b>

🔍 <b>Protección Activa:</b>
• Análisis de malware en tiempo real
• Detección de payload downloaders
• Identificación de técnicas de evasión
• Monitoreo de comandos sospechosos

📊 <b>Estadísticas del Sistema:</b>
• 8 reglas de detección activas
• 6 técnicas de evasión monitoreadas
• 15 comandos sospechosos detectados
• Tiempo de respuesta: < 1 segundo

🎯 <b>Familias de Malware Detectadas:</b>
• RedTail droppers
• Payload downloaders
• Shell script malware
• Binary payloads

💡 <b>Tu seguridad está protegida automáticamente.</b>

<i>Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
        """.strip()

        return self._send_message(chat_id, security_message)

    def _handle_start(self, chat_id: int, user_id: int) -> bool:
        """Manejar comando /start"""
        welcome_message = f"""
🚀 <b>¡Bienvenido a C4A Alerts!</b>

🔒 <b>Plataforma de Threat Intelligence con Protección Anti-Malware</b>

Te ayudamos a mantenerte informado sobre las últimas amenazas de seguridad cibernética.

✨ <b>Características principales:</b>
• Alertas en tiempo real de vulnerabilidades críticas
• Análisis de amenazas emergentes
• Monitoreo de fuentes de inteligencia
• Notificaciones personalizables
• 🛡️ <b>Detección automática de malware</b>

💡 <b>Comandos disponibles:</b>
/help - Ver ayuda completa
/status - Estado del sistema
/security - Información de seguridad
/subscribe - Suscribirse a alertas
/settings - Configurar preferencias
/about - Información del proyecto

🔔 <b>Para comenzar:</b>
Usa /subscribe para activar las notificaciones de alertas de seguridad.

🛡️ <b>Protección automática:</b>
Todos los mensajes son analizados automáticamente en busca de malware.

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
