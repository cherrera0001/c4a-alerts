#!/usr/bin/env python3
"""
ADVANCED COUNTERATTACK - Sistema de contraataque sofisticado
Múltiples estrategias para neutralizar atacantes
"""

import os
import requests
import json
import time
import random
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class AdvancedCounterattack:
    def __init__(self):
        self.token = os.getenv('TELEGRAM_TOKEN', '')
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.attackers = {}
        self.counterattack_strategies = {
            'intelligence_gathering': self.gather_intelligence,
            'psychological_warfare': self.psychological_warfare,
            'technical_counter': self.technical_counter,
            'social_engineering': self.social_engineering,
            'deception': self.deception_tactics
        }

    def gather_intelligence(self, attacker_info):
        """Recolectar inteligencia del atacante"""
        print("🕵️ Recolectando inteligencia...")

        # Simular análisis profundo
        analysis_message = """🔍 ANÁLISIS DE AMENAZA EN CURSO...
📊 Perfilando comportamiento del atacante
🌍 Geolocalizando origen de la amenaza
🔗 Mapeando red de contactos
📱 Analizando patrones de comunicación
⏳ Procesando datos de inteligencia...
✅ Inteligencia recolectada y almacenada"""

        self.send_delayed_message(attacker_info['user_id'], analysis_message, delay=3)

        # Simular más análisis
        time.sleep(2)
        follow_up = """📈 DATOS DE INTELIGENCIA:
👤 Usuario: @{username}
🆔 ID: {user_id}
🌍 Región: Detectada
📱 Dispositivo: Identificado
🔗 Conexión: Monitoreada
⚠️ Amenaza: Clasificada""".format(**attacker_info)

        self.send_delayed_message(attacker_info['user_id'], follow_up, delay=2)

    def psychological_warfare(self, attacker_info):
        """Guerra psicológica contra el atacante"""
        print("🧠 Iniciando guerra psicológica...")

        messages = [
            "🤖 Sistema de defensa activado...",
            "🛡️ Protocolos de seguridad ejecutándose...",
            "⚠️ Amenaza detectada y registrada...",
            "📊 Analizando patrones de comportamiento...",
            "🔒 Activando contramedidas...",
            "🚨 Sistema de alerta activado...",
            "📡 Transmitiendo datos a autoridades...",
            "⚡ Ejecutando protocolos de emergencia..."
        ]

        for i, message in enumerate(messages):
            self.send_delayed_message(attacker_info['user_id'], message, delay=i*2)
            time.sleep(1)

    def technical_counter(self, attacker_info):
        """Contramedidas técnicas"""
        print("⚡ Aplicando contramedidas técnicas...")

        # Simular bloqueo técnico
        block_message = """🚫 ACCESO RESTRINGIDO
🔒 Tu actividad ha sido detectada como maliciosa
🛡️ Sistema de protección activado
📊 Tu información ha sido registrada
⚠️ Acceso temporalmente suspendido
🔍 Monitoreo de actividad en curso"""

        self.send_delayed_message(attacker_info['user_id'], block_message, delay=1)

        # Simular análisis técnico
        time.sleep(3)
        tech_analysis = """🔧 ANÁLISIS TÉCNICO:
📱 Dispositivo: {device}
🌐 IP: {ip}
🔗 User-Agent: {user_agent}
📊 Fingerprint: {fingerprint}
⚠️ Vulnerabilidades: Detectadas
🛡️ Protección: Activada""".format(
            device="Android/iOS",
            ip="***.***.***.***",
            user_agent="TelegramBot/1.0",
            fingerprint="HASH_123456"
        )

        self.send_delayed_message(attacker_info['user_id'], tech_analysis, delay=2)

    def social_engineering(self, attacker_info):
        """Contra-ingeniería social"""
        print("🎭 Aplicando contra-ingeniería social...")

        # Hacer que el atacante piense que está siendo observado
        messages = [
            "👁️ Sistema de vigilancia activo...",
            "📹 Cámaras de seguridad: FUNCIONANDO",
            "🎯 Objetivo: IDENTIFICADO",
            "📱 Dispositivo: RASTREADO",
            "🌍 Ubicación: CONFIRMADA",
            "👮 Autoridades: NOTIFICADAS",
            "📊 Evidencia: RECOPILADA",
            "⚖️ Caso: EN PROCESO"
        ]

        for i, message in enumerate(messages):
            self.send_delayed_message(attacker_info['user_id'], message, delay=i*1.5)
            time.sleep(0.5)

    def deception_tactics(self, attacker_info):
        """Tácticas de engaño"""
        print("🎭 Aplicando tácticas de engaño...")

        # Hacer que el atacante piense que está teniendo éxito
        fake_success = """🎯 VULNERABILIDAD DETECTADA
🔓 Acceso concedido temporalmente
📊 Recolectando datos del sistema...
⏳ Procesando información...
✅ Datos extraídos exitosamente
🔗 Conectando a servidor remoto...
⚠️ ADVERTENCIA: Esta es una trampa"""

        self.send_delayed_message(attacker_info['user_id'], fake_success, delay=1)

        # Luego revelar que es una trampa
        time.sleep(5)
        trap_reveal = """🎣 ¡TRAMPA ACTIVADA!
🕵️ Has sido atrapado por nuestro honeypot
📊 Tu información ha sido recolectada
🔒 Tu actividad ha sido registrada
⚠️ Las autoridades han sido notificadas
🚫 Acceso bloqueado permanentemente"""

        self.send_delayed_message(attacker_info['user_id'], trap_reveal, delay=1)

    def send_delayed_message(self, user_id, message, delay=1):
        """Enviar mensaje con delay"""
        try:
            time.sleep(delay)
            response = requests.post(
                f"{self.base_url}/sendMessage",
                json={
                    'chat_id': user_id,
                    'text': message,
                    'parse_mode': 'HTML'
                }
            )
            if response.status_code == 200:
                print(f"📤 Mensaje enviado a {user_id}")
            else:
                print(f"❌ Error enviando mensaje: {response.status_code}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def execute_counterattack(self, attacker_info):
        """Ejecutar contraataque completo"""
        print(f"🚨 EJECUTANDO CONTRAATAQUE CONTRA @{attacker_info['username']}")
        print("=" * 60)

        # Seleccionar estrategias aleatorias
        strategies = random.sample(list(self.counterattack_strategies.keys()), 3)

        for strategy in strategies:
            print(f"🎯 Ejecutando: {strategy}")
            self.counterattack_strategies[strategy](attacker_info)
            time.sleep(2)

        # Mensaje final de intimidación
        final_message = """⚡ CONTRAATAQUE COMPLETADO
🛡️ Sistema de defensa: ACTIVO
📊 Inteligencia: RECOPILADA
🔒 Protección: REFORZADA
⚠️ Futuros ataques: BLOQUEADOS
🎯 Objetivo: NEUTRALIZADO"""

        self.send_delayed_message(attacker_info['user_id'], final_message, delay=3)

    def analyze_and_counterattack(self):
        """Analizar mensajes y contraatacar"""
        print("🕵️ Analizando mensajes para contraataque...")

        try:
            response = requests.get(f"{self.base_url}/getUpdates")
            if response.status_code == 200:
                updates = response.json().get('result', [])

                for update in updates:
                    if 'message' in update:
                        message = update['message']
                        if self.is_malicious(message):
                            attacker_info = self.extract_attacker_info(message)
                            self.execute_counterattack(attacker_info)
                            return True

            return False

        except Exception as e:
            print(f"❌ Error analizando mensajes: {e}")
            return False

    def is_malicious(self, message):
        """Detectar si un mensaje es malicioso"""
        if 'text' not in message:
            return False

        text = message['text'].lower()
        malicious_patterns = [
            'free hd', 'cute_cat_robot', 'get-', 'start=',
            'malware', 'virus', 'spam', 'scam', 'click here',
            'earn money', 'make money', 'free money'
        ]

        return any(pattern in text for pattern in malicious_patterns)

    def extract_attacker_info(self, message):
        """Extraer información del atacante"""
        return {
            'user_id': message['from']['id'],
            'username': message['from'].get('username', 'unknown'),
            'first_name': message['from'].get('first_name', 'unknown'),
            'message': message.get('text', ''),
            'timestamp': datetime.now().isoformat()
        }

    def continuous_counterattack_mode(self, duration_minutes=30):
        """Modo de contraataque continuo"""
        print(f"⚡ Iniciando modo de contraataque continuo por {duration_minutes} minutos...")
        print("🎯 Esperando atacantes para contraatacar...")

        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        attack_count = 0

        while time.time() < end_time:
            if self.analyze_and_counterattack():
                attack_count += 1
                print(f"🎯 Contraataque #{attack_count} ejecutado")

            time.sleep(10)  # Verificar cada 10 segundos

        print(f"✅ Modo de contraataque completado. Total de contraataques: {attack_count}")

def main():
    """Función principal"""
    print("⚡ ADVANCED COUNTERATTACK - Sistema de Contraataque")
    print("=" * 60)

    counterattack = AdvancedCounterattack()

    print("📋 ESTRATEGIAS DE CONTRAATAQUE:")
    print("1. Modo de contraataque continuo (30 min)")
    print("2. Analizar y contraatacar una vez")
    print("3. Configurar estrategias personalizadas")
    print("4. Ver estadísticas de contraataques")
    print("5. Salir")

    choice = input("\n🔢 Selecciona opción (1-5): ").strip()

    if choice == '1':
        counterattack.continuous_counterattack_mode()
    elif choice == '2':
        if counterattack.analyze_and_counterattack():
            print("🎯 Contraataque ejecutado exitosamente")
        else:
            print("📊 No se detectaron amenazas para contraatacar")
    elif choice == '3':
        print("⚙️ Configuración de estrategias personalizadas")
        print("🎯 Estrategias disponibles:")
        for strategy in counterattack.counterattack_strategies.keys():
            print(f"   - {strategy}")
    elif choice == '4':
        print("📊 Estadísticas de contraataques")
        print("🎯 Sistema listo para contraatacar")
    elif choice == '5':
        print("👋 ¡Hasta luego!")
    else:
        print("❌ Opción inválida")

if __name__ == "__main__":
    main()
