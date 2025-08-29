#!/usr/bin/env python3
"""
HONEYPOT TRAP - Sistema de contraataque inteligente
Atrapar atacantes y recolectar inteligencia
"""

import os
import requests
import json
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class HoneypotTrap:
    def __init__(self):
        self.token = os.getenv('TELEGRAM_TOKEN', '')
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.attackers_db = {}
        self.suspicious_patterns = [
            'free hd', 'cute_cat_robot', 'get-', 'start=',
            'malware', 'virus', 'spam', 'scam'
        ]

    def setup_honeypot(self):
        """Configurar el bot como honeypot"""
        print("🕵️ CONFIGURANDO HONEYPOT TRAP...")

        # Configurar bot para parecer vulnerable
        honeypot_description = """🔒 C4A Alerts - Threat Intelligence Platform
⚠️ Sistema de alertas de seguridad
📊 Monitoreo en tiempo real
🔗 Integración con múltiples fuentes
💡 Análisis de amenazas avanzado"""

        try:
            response = requests.post(
                f"{self.base_url}/setMyDescription",
                json={'description': honeypot_description}
            )
            print("✅ Bot configurado como honeypot")
        except Exception as e:
            print(f"❌ Error: {e}")

    def analyze_message(self, message_data):
        """Analizar mensaje en busca de amenazas"""
        if 'text' not in message_data:
            return False

        text = message_data['text'].lower()
        user_id = message_data['from']['id']
        username = message_data['from'].get('username', 'unknown')
        first_name = message_data['from'].get('first_name', 'unknown')

        # Detectar patrones sospechosos
        threat_score = 0
        detected_patterns = []

        for pattern in self.suspicious_patterns:
            if pattern in text:
                threat_score += 10
                detected_patterns.append(pattern)

        # Detectar URLs maliciosas
        if 'http' in text and ('cute_cat_robot' in text or 'get-' in text):
            threat_score += 50
            detected_patterns.append('malicious_url')

        # Detectar spam
        if len(text) < 10 and any(word in text for word in ['free', 'hd', 'click']):
            threat_score += 30
            detected_patterns.append('spam')

        if threat_score > 0:
            self.log_attacker(user_id, username, first_name, text, threat_score, detected_patterns)
            return True

        return False

    def log_attacker(self, user_id, username, first_name, message, threat_score, patterns):
        """Registrar información del atacante"""
        timestamp = datetime.now().isoformat()

        attacker_info = {
            'user_id': user_id,
            'username': username,
            'first_name': first_name,
            'message': message,
            'threat_score': threat_score,
            'patterns': patterns,
            'timestamp': timestamp,
            'ip_info': self.get_ip_info(user_id)
        }

        self.attackers_db[user_id] = attacker_info

        print(f"🚨 ATACANTE DETECTADO!")
        print(f"👤 Usuario: @{username} ({first_name})")
        print(f"🆔 ID: {user_id}")
        print(f"📝 Mensaje: {message}")
        print(f"⚠️ Threat Score: {threat_score}")
        print(f"🎯 Patrones: {patterns}")
        print(f"🕐 Timestamp: {timestamp}")
        print("-" * 50)

        # Guardar en archivo
        self.save_attack_log(attacker_info)

        # Enviar respuesta trampa
        self.send_trap_response(user_id, threat_score)

    def send_trap_response(self, user_id, threat_score):
        """Enviar respuesta trampa al atacante"""
        if threat_score > 50:
            # Atacante de alto riesgo - respuesta más elaborada
            trap_message = """🔍 Analizando amenaza detectada...
📊 Severidad: CRÍTICA
🛡️ Activando protocolos de seguridad
⏳ Procesando datos de amenaza...
✅ Análisis completado - Amenaza registrada"""
        else:
            # Atacante de bajo riesgo - respuesta básica
            trap_message = """🤖 C4A Alerts - Sistema de Threat Intelligence
📡 Monitoreando amenazas en tiempo real
🔒 Protegiendo infraestructura crítica
📊 Recolectando datos de inteligencia"""

        try:
            response = requests.post(
                f"{self.base_url}/sendMessage",
                json={
                    'chat_id': user_id,
                    'text': trap_message,
                    'parse_mode': 'HTML'
                }
            )
            print(f"🎣 Respuesta trampa enviada a {user_id}")
        except Exception as e:
            print(f"❌ Error enviando trampa: {e}")

    def get_ip_info(self, user_id):
        """Obtener información del atacante (simulado)"""
        # En un caso real, esto requeriría configuración adicional
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }

    def save_attack_log(self, attacker_info):
        """Guardar log de ataque"""
        log_file = 'attackers_log.json'

        try:
            # Cargar logs existentes
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            else:
                logs = []

            # Agregar nuevo ataque
            logs.append(attacker_info)

            # Guardar
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)

            print(f"📝 Ataque registrado en {log_file}")
        except Exception as e:
            print(f"❌ Error guardando log: {e}")

    def generate_intelligence_report(self):
        """Generar reporte de inteligencia"""
        if not self.attackers_db:
            print("📊 No hay ataques registrados")
            return

        print("\n" + "=" * 60)
        print("🕵️ REPORTE DE INTELIGENCIA - HONEYPOT")
        print("=" * 60)

        total_attacks = len(self.attackers_db)
        avg_threat_score = sum(a['threat_score'] for a in self.attackers_db.values()) / total_attacks

        print(f"📊 Total de atacantes: {total_attacks}")
        print(f"⚠️ Threat Score promedio: {avg_threat_score:.1f}")
        print(f"🕐 Período: {min(a['timestamp'] for a in self.attackers_db.values())} - {max(a['timestamp'] for a in self.attackers_db.values())}")

        # Patrones más comunes
        all_patterns = []
        for attacker in self.attackers_db.values():
            all_patterns.extend(attacker['patterns'])

        pattern_counts = {}
        for pattern in all_patterns:
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        print("\n🎯 PATRONES MÁS COMUNES:")
        for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"   {pattern}: {count} veces")

        print("\n👥 TOP ATACANTES:")
        sorted_attackers = sorted(self.attackers_db.values(), key=lambda x: x['threat_score'], reverse=True)
        for i, attacker in enumerate(sorted_attackers[:5]):
            print(f"   {i+1}. @{attacker['username']} - Score: {attacker['threat_score']}")

    def monitor_attacks(self, duration_minutes=60):
        """Monitorear ataques en tiempo real"""
        print(f"🕵️ Iniciando monitoreo por {duration_minutes} minutos...")
        print("⏳ Esperando ataques...")

        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)

        while time.time() < end_time:
            try:
                # Obtener mensajes recientes
                response = requests.get(f"{self.base_url}/getUpdates")
                if response.status_code == 200:
                    updates = response.json().get('result', [])

                    for update in updates:
                        if 'message' in update:
                            message = update['message']
                            if self.analyze_message(message):
                                print("🎣 ¡Atacante atrapado!")

                time.sleep(10)  # Verificar cada 10 segundos

            except Exception as e:
                print(f"❌ Error en monitoreo: {e}")
                time.sleep(30)

def main():
    """Función principal"""
    print("🕵️ HONEYPOT TRAP - Sistema de Contraataque")
    print("=" * 60)

    honeypot = HoneypotTrap()

    print("📋 OPCIONES:")
    print("1. Configurar honeypot")
    print("2. Monitorear ataques (60 min)")
    print("3. Generar reporte de inteligencia")
    print("4. Ver logs de atacantes")
    print("5. Salir")

    choice = input("\n🔢 Selecciona opción (1-5): ").strip()

    if choice == '1':
        honeypot.setup_honeypot()
    elif choice == '2':
        honeypot.monitor_attacks()
    elif choice == '3':
        honeypot.generate_intelligence_report()
    elif choice == '4':
        if os.path.exists('attackers_log.json'):
            with open('attackers_log.json', 'r', encoding='utf-8') as f:
                logs = json.load(f)
            print(f"📊 Total de ataques registrados: {len(logs)}")
        else:
            print("📊 No hay logs de ataques")
    elif choice == '5':
        print("👋 ¡Hasta luego!")
    else:
        print("❌ Opción inválida")

if __name__ == "__main__":
    main()
