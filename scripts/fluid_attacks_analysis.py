#!/usr/bin/env python3
"""
🔒 ANÁLISIS DE SEGURIDAD CON FLUID ATTACKS
Script para integrar Fluid Attacks API y realizar análisis automático de seguridad
"""

import requests
import json
import os
import time
import base64
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

class FluidAttacksAnalyzer:
    """Analizador de seguridad usando Fluid Attacks API"""

    def __init__(self):
        load_dotenv()
        self.api_token = os.getenv("FLUID_ATTACKS_TOKEN")

        if not self.api_token:
            print("❌ FLUID_ATTACKS_TOKEN no encontrado en variables de entorno")
            print("💡 Asegúrate de que el archivo .env esté en el directorio raíz")
            return

        self.base_url = "https://app.fluidattacks.com/api"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def validate_token(self):
        """Validar que el token de Fluid Attacks sea válido"""
        if not self.api_token:
            print("❌ Token no configurado")
            return False

        try:
            print(f"🔍 Validando token de Fluid Attacks...")
            print(f"   📝 Token: {self.api_token[:20]}...")

            response = requests.get(
                f"{self.base_url}/v1/me",
                headers=self.headers,
                timeout=30
            )

            print(f"   📊 Status Code: {response.status_code}")

            if response.status_code == 200:
                try:
                    user_info = response.json()
                    print("✅ Token de Fluid Attacks válido")
                    print(f"   👤 Usuario: {user_info.get('user_email', 'N/A')}")
                    print(f"   🏢 Organización: {user_info.get('organization_name', 'N/A')}")
                    return True
                except json.JSONDecodeError as e:
                    print(f"❌ Error decodificando respuesta: {e}")
                    print(f"   📄 Respuesta: {response.text[:200]}...")
                    return False
            else:
                print(f"❌ Error validando token: {response.status_code}")
                print(f"   📄 Respuesta: {response.text[:200]}...")
                return False

        except requests.exceptions.RequestException as e:
            print(f"❌ Error de conexión: {e}")
            return False
        except Exception as e:
            print(f"❌ Error inesperado: {e}")
            return False

    def create_analysis_request(self, repository_url=None, branch="main"):
        """Crear solicitud de análisis de seguridad"""

        # Configuración del análisis
        analysis_config = {
            "repository": {
                "url": repository_url or "https://github.com/your-username/c4a-alerts",
                "branch": branch,
                "credentials": {
                    "type": "HTTPS"
                }
            },
            "analysis_type": "SAST",  # Static Application Security Testing
            "language": "python",
            "framework": "fastapi",
            "severity_levels": ["critical", "high", "medium", "low"],
            "include_patterns": [
                "*.py",
                "*.js",
                "*.ts",
                "*.json",
                "*.yaml",
                "*.yml"
            ],
            "exclude_patterns": [
                "venv/*",
                "node_modules/*",
                "__pycache__/*",
                "*.pyc",
                ".git/*"
            ]
        }

        try:
            response = requests.post(
                f"{self.base_url}/v1/analyses",
                headers=self.headers,
                json=analysis_config,
                timeout=60
            )

            if response.status_code == 201:
                analysis_data = response.json()
                print("✅ Análisis de seguridad iniciado")
                print(f"   🆔 ID del análisis: {analysis_data.get('id')}")
                print(f"   📊 Estado: {analysis_data.get('status')}")
                return analysis_data.get('id')
            else:
                print(f"❌ Error iniciando análisis: {response.status_code}")
                print(f"   Respuesta: {response.text}")
                return None

        except Exception as e:
            print(f"❌ Error creando análisis: {e}")
            return None

    def get_analysis_status(self, analysis_id):
        """Obtener estado del análisis"""
        try:
            response = requests.get(
                f"{self.base_url}/v1/analyses/{analysis_id}",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Error obteniendo estado: {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Error consultando análisis: {e}")
            return None

    def wait_for_analysis_completion(self, analysis_id, max_wait_time=1800):
        """Esperar a que el análisis se complete"""
        print(f"⏳ Esperando que el análisis {analysis_id} se complete...")

        start_time = time.time()
        while time.time() - start_time < max_wait_time:
            status_data = self.get_analysis_status(analysis_id)

            if not status_data:
                time.sleep(30)
                continue

            status = status_data.get('status')
            progress = status_data.get('progress', 0)

            print(f"   📊 Progreso: {progress}% - Estado: {status}")

            if status in ['completed', 'failed']:
                return status_data

            time.sleep(60)  # Esperar 1 minuto antes de consultar nuevamente

        print("⏰ Tiempo de espera agotado")
        return None

    def get_vulnerabilities(self, analysis_id):
        """Obtener vulnerabilidades encontradas"""
        try:
            response = requests.get(
                f"{self.base_url}/v1/analyses/{analysis_id}/vulnerabilities",
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ Error obteniendo vulnerabilidades: {response.status_code}")
                return None

        except Exception as e:
            print(f"❌ Error consultando vulnerabilidades: {e}")
            return None

    def generate_security_report(self, vulnerabilities, analysis_id):
        """Generar reporte de seguridad"""
        if not vulnerabilities:
            print("✅ No se encontraron vulnerabilidades")
            return

        print("\n" + "=" * 80)
        print("🔒 REPORTE DE SEGURIDAD - FLUID ATTACKS")
        print("=" * 80)
        print(f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🆔 Análisis ID: {analysis_id}")
        print(f"📊 Total de vulnerabilidades: {len(vulnerabilities)}")

        # Agrupar por severidad
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print("\n📈 RESUMEN POR SEVERIDAD:")
        for severity, count in severity_counts.items():
            emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(severity, '⚪')
            print(f"   {emoji} {severity.upper()}: {count}")

        # Mostrar vulnerabilidades críticas y altas
        critical_vulns = [v for v in vulnerabilities if v.get('severity') in ['critical', 'high']]

        if critical_vulns:
            print(f"\n🚨 VULNERABILIDADES CRÍTICAS Y ALTAS ({len(critical_vulns)}):")
            for i, vuln in enumerate(critical_vulns[:10], 1):  # Mostrar solo las primeras 10
                print(f"\n{i}. {vuln.get('title', 'Sin título')}")
                print(f"   🔴 Severidad: {vuln.get('severity', 'N/A')}")
                print(f"   📍 Archivo: {vuln.get('file_path', 'N/A')}")
                print(f"   📍 Línea: {vuln.get('line_number', 'N/A')}")
                print(f"   📝 Descripción: {vuln.get('description', 'N/A')[:200]}...")
                print(f"   🛡️ Recomendación: {vuln.get('recommendation', 'N/A')[:200]}...")

        # Guardar reporte en archivo
        self.save_report_to_file(vulnerabilities, analysis_id)

    def save_report_to_file(self, vulnerabilities, analysis_id):
        """Guardar reporte en archivo JSON"""
        report_data = {
            "analysis_id": analysis_id,
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

        report_file = f"security_report_{analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            print(f"\n💾 Reporte guardado en: {report_file}")

        except Exception as e:
            print(f"❌ Error guardando reporte: {e}")

    def analyze_local_code(self):
        """Analizar código local (simulación)"""
        print("🔍 Analizando código local...")

        # Simular análisis local
        local_vulnerabilities = [
            {
                "title": "Hardcoded Credentials",
                "severity": "critical",
                "file_path": "scripts/configure_public_bot.py",
                "line_number": 11,
                "description": "Se encontraron credenciales hardcodeadas en el código fuente",
                "recommendation": "Usar variables de entorno para todas las credenciales"
            },
            {
                "title": "Insecure JWT Implementation",
                "severity": "high",
                "file_path": "c4aalerts/app/auth/jwt_auth.py",
                "line_number": 45,
                "description": "Implementación de JWT sin validación adecuada de expiración",
                "recommendation": "Implementar validación de expiración y refresh tokens"
            }
        ]

        print(f"✅ Análisis local completado - {len(local_vulnerabilities)} vulnerabilidades encontradas")
        return local_vulnerabilities

def main():
    """Función principal"""
    print("=" * 80)
    print("🔒 ANÁLISIS DE SEGURIDAD CON FLUID ATTACKS")
    print("=" * 80)

    analyzer = FluidAttacksAnalyzer()

    # Validar token
    if not analyzer.validate_token():
        print("❌ Token de Fluid Attacks inválido o no configurado")
        print("💡 Configura FLUID_ATTACKS_TOKEN en tu archivo .env")
        return

    print("\n🎯 OPCIONES DE ANÁLISIS:")
    print("1. Análisis completo con Fluid Attacks API")
    print("2. Análisis local (simulación)")
    print("3. Solo validar configuración")

    choice = input("\nSelecciona una opción (1-3): ").strip()

    if choice == "1":
        # Análisis completo
        print("\n🚀 Iniciando análisis completo...")

        analysis_id = analyzer.create_analysis_request()
        if analysis_id:
            # Esperar completación
            result = analyzer.wait_for_analysis_completion(analysis_id)
            if result:
                # Obtener vulnerabilidades
                vulnerabilities = analyzer.get_vulnerabilities(analysis_id)
                analyzer.generate_security_report(vulnerabilities, analysis_id)

    elif choice == "2":
        # Análisis local
        print("\n🔍 Realizando análisis local...")
        vulnerabilities = analyzer.analyze_local_code()
        analyzer.generate_security_report(vulnerabilities, "LOCAL_ANALYSIS")

    elif choice == "3":
        print("✅ Configuración validada correctamente")

    else:
        print("❌ Opción inválida")

if __name__ == "__main__":
    main()
