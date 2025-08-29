#!/usr/bin/env python3
"""
🔍 ANÁLISIS RÁPIDO DE SEGURIDAD
Script para realizar análisis rápido de vulnerabilidades comunes en el código
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

class QuickSecurityScanner:
    """Scanner rápido de seguridad para código Python"""

    def __init__(self):
        self.vulnerabilities = []
        self.scan_patterns = {
            "hardcoded_credentials": {
                "pattern": r'(password|token|secret|key)\s*=\s*["\'][^"\']+["\']',
                "severity": "critical",
                "description": "Credenciales hardcodeadas en el código"
            },
            "sql_injection": {
                "pattern": r'execute\(.*\+.*\)|cursor\.execute\(.*\+.*\)',
                "severity": "high",
                "description": "Posible inyección SQL"
            },
            "command_injection": {
                "pattern": r'os\.system\(.*\+.*\)|subprocess\.call\(.*\+.*\)',
                "severity": "high",
                "description": "Posible inyección de comandos"
            },
            "weak_crypto": {
                "pattern": r'hashlib\.md5\(|hashlib\.sha1\(',
                "severity": "medium",
                "description": "Uso de algoritmos criptográficos débiles"
            },
            "debug_enabled": {
                "pattern": r'DEBUG\s*=\s*True|debug\s*=\s*True',
                "severity": "medium",
                "description": "Modo debug habilitado en producción"
            },
            "insecure_headers": {
                "pattern": r'Access-Control-Allow-Origin:\s*\*',
                "severity": "medium",
                "description": "CORS configurado de forma insegura"
            },
            "file_path_traversal": {
                "pattern": r'open\(.*\+.*\)|file\(.*\+.*\)',
                "severity": "high",
                "description": "Posible path traversal"
            },
            "eval_usage": {
                "pattern": r'eval\(|exec\(',
                "severity": "critical",
                "description": "Uso de eval() o exec() - muy peligroso"
            },
            "weak_random": {
                "pattern": r'random\.randint\(|random\.choice\(',
                "severity": "medium",
                "description": "Uso de random en lugar de secrets"
            },
            "insecure_deserialization": {
                "pattern": r'pickle\.loads\(|yaml\.load\(',
                "severity": "high",
                "description": "Deserialización insegura"
            }
        }

    def scan_file(self, file_path):
        """Escanear un archivo en busca de vulnerabilidades"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            file_vulns = []
            lines = content.split('\n')

            for vuln_type, config in self.scan_patterns.items():
                pattern = config['pattern']
                matches = re.finditer(pattern, content, re.IGNORECASE)

                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    line_content = lines[line_number - 1].strip()

                    file_vulns.append({
                        "type": vuln_type,
                        "severity": config['severity'],
                        "description": config['description'],
                        "line_number": line_number,
                        "line_content": line_content,
                        "match": match.group()
                    })

            return file_vulns

        except Exception as e:
            print(f"❌ Error escaneando {file_path}: {e}")
            return []

    def scan_directory(self, directory="."):
        """Escanear directorio completo"""
        print(f"🔍 Escaneando directorio: {directory}")

        # Archivos a escanear
        file_extensions = ['.py', '.js', '.ts', '.json', '.yaml', '.yml', '.env']
        exclude_dirs = ['venv', 'node_modules', '__pycache__', '.git', '.vscode']

        for root, dirs, files in os.walk(directory):
            # Excluir directorios
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    file_vulns = self.scan_file(file_path)

                    if file_vulns:
                        for vuln in file_vulns:
                            vuln['file_path'] = file_path
                            self.vulnerabilities.append(vuln)

    def generate_report(self):
        """Generar reporte de vulnerabilidades"""
        if not self.vulnerabilities:
            print("✅ No se encontraron vulnerabilidades en el análisis rápido")
            return

        print("\n" + "=" * 80)
        print("🔒 REPORTE DE ANÁLISIS RÁPIDO DE SEGURIDAD")
        print("=" * 80)
        print(f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📊 Total de vulnerabilidades: {len(self.vulnerabilities)}")

        # Agrupar por severidad
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
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
        critical_vulns = [v for v in self.vulnerabilities if v['severity'] in ['critical', 'high']]

        if critical_vulns:
            print(f"\n🚨 VULNERABILIDADES CRÍTICAS Y ALTAS ({len(critical_vulns)}):")
            for i, vuln in enumerate(critical_vulns, 1):
                print(f"\n{i}. {vuln['description']}")
                print(f"   🔴 Severidad: {vuln['severity'].upper()}")
                print(f"   📍 Archivo: {vuln['file_path']}")
                print(f"   📍 Línea: {vuln['line_number']}")
                print(f"   📝 Código: {vuln['line_content']}")
                print(f"   🎯 Tipo: {vuln['type']}")

        # Guardar reporte
        self.save_report()

    def save_report(self):
        """Guardar reporte en archivo"""
        report_data = {
            "scan_date": datetime.now().isoformat(),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }

        report_file = f"quick_security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            print(f"\n💾 Reporte guardado en: {report_file}")

        except Exception as e:
            print(f"❌ Error guardando reporte: {e}")

def main():
    """Función principal"""
    print("=" * 80)
    print("🔍 ANÁLISIS RÁPIDO DE SEGURIDAD")
    print("=" * 80)

    scanner = QuickSecurityScanner()

    # Escanear directorio actual
    scanner.scan_directory()

    # Generar reporte
    scanner.generate_report()

    print("\n" + "=" * 80)
    print("✅ Análisis rápido completado")
    print("💡 Para análisis más profundo, ejecuta: python scripts/fluid_attacks_analysis.py")
    print("=" * 80)

if __name__ == "__main__":
    main()
