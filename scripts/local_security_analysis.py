#!/usr/bin/env python3
"""
🔒 ANÁLISIS LOCAL DE SEGURIDAD
Script para realizar análisis de seguridad local del código
"""

import os
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

class LocalSecurityAnalyzer:
    """Analizador de seguridad local"""

    def __init__(self):
        self.vulnerabilities = []
        self.scan_patterns = {
            'hardcoded_credentials': {
                'patterns': [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'token\s*=\s*["\'][^"\']+["\']',
                    r'secret\s*=\s*["\'][^"\']+["\']',
                    r'api_key\s*=\s*["\'][^"\']+["\']',
                    r'FLUID_ATTACKS_TOKEN\s*=\s*["\'][^"\']+["\']',
                    r'TELEGRAM_TOKEN\s*=\s*["\'][^"\']+["\']',
                ],
                'severity': 'critical',
                'description': 'Credenciales hardcodeadas en el código'
            },
            'weak_crypto': {
                'patterns': [
                    r'hashlib\.md5\(',
                    r'hashlib\.sha1\(',
                    r'base64\.b64encode\(',
                ],
                'severity': 'medium',
                'description': 'Uso de algoritmos criptográficos débiles'
            },
            'debug_enabled': {
                'patterns': [
                    r'DEBUG\s*=\s*True',
                    r'debug\s*=\s*True',
                ],
                'severity': 'medium',
                'description': 'Modo debug habilitado en producción'
            },
            'eval_usage': {
                'patterns': [
                    r'eval\(',
                    r'exec\(',
                ],
                'severity': 'critical',
                'description': 'Uso de eval() o exec() - muy peligroso'
            },
            'sql_injection': {
                'patterns': [
                                    r'f".*SELECT.*\{.*\}',
                r'f".*INSERT.*\{.*\}',
                r'f".*UPDATE.*\{.*\}',
                r'f".*DELETE.*\{.*\}',
                ],
                'severity': 'high',
                'description': 'Posible inyección SQL'
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./',
                    r'\.\.\\',
                    r'open\(.*\.\.',
                ],
                'severity': 'high',
                'description': 'Posible path traversal'
            }
        }

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Escanear un archivo en busca de vulnerabilidades"""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                for line_num, line in enumerate(lines, 1):
                    for vuln_type, config in self.scan_patterns.items():
                        for pattern in config['patterns']:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Verificar si es un falso positivo
                                if self._is_false_positive(line, vuln_type):
                                    continue

                                vulnerabilities.append({
                                    'type': vuln_type,
                                    'severity': config['severity'],
                                    'description': config['description'],
                                    'file_path': file_path,
                                    'line_number': line_num,
                                    'line_content': line.strip(),
                                    'match': re.search(pattern, line, re.IGNORECASE).group()
                                })

        except Exception as e:
            print(f"Error escaneando {file_path}: {e}")

        return vulnerabilities

    def _is_false_positive(self, line: str, vuln_type: str) -> bool:
        """Verificar si es un falso positivo"""
        line_lower = line.lower()

        # Falsos positivos para eval_usage
        if vuln_type == 'eval_usage':
            if 'description' in line_lower or 'pattern' in line_lower:
                return True

        # Falsos positivos para hardcoded_credentials
        if vuln_type == 'hardcoded_credentials':
            if 'your_' in line_lower or 'placeholder' in line_lower:
                return True

        return False

    def scan_directory(self, directory: str = '.') -> List[Dict[str, Any]]:
        """Escanear directorio completo"""
        all_vulnerabilities = []

        # Archivos a escanear
        include_patterns = ['*.py', '*.js', '*.ts', '*.json', '*.yaml', '*.yml']
        exclude_patterns = ['venv', 'node_modules', '__pycache__', '.git', '.env']

        for pattern in include_patterns:
            for file_path in Path(directory).rglob(pattern):
                # Verificar exclusiones
                if any(exclude in str(file_path).split(os.sep) for exclude in exclude_patterns):
                    continue

                try:
                    vulnerabilities = self.scan_file(str(file_path))
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    print(f"⚠️ Error escaneando {file_path}: {e}")
                    continue

        return all_vulnerabilities

    def generate_report(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generar reporte de seguridad"""
        # Agrupar por severidad
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': severity_counts,
            'vulnerabilities': vulnerabilities
        }

    def save_report(self, report: Dict[str, Any], filename: str = None) -> str:
        """Guardar reporte en archivo"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'local_security_scan_{timestamp}.json'

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return filename

    def print_report(self, report: Dict[str, Any]):
        """Imprimir reporte en consola"""
        print("=" * 80)
        print("REPORTE DE ANALISIS LOCAL DE SEGURIDAD")
        print("=" * 80)
        print(f"Fecha: {report['scan_date']}")
        print(f"Total de vulnerabilidades: {report['total_vulnerabilities']}")

        # Resumen por severidad
        print("\nRESUMEN POR SEVERIDAD:")
        for severity, count in report['severity_distribution'].items():
            print(f"   {severity.upper()}: {count}")

        # Mostrar vulnerabilidades críticas y altas
        critical_vulns = [v for v in report['vulnerabilities']
                         if v['severity'] in ['critical', 'high']]

        if critical_vulns:
            print(f"\nVULNERABILIDADES CRITICAS Y ALTAS ({len(critical_vulns)}):")
            for i, vuln in enumerate(critical_vulns, 1):
                print(f"\n{i}. {vuln['description']}")
                print(f"   Severidad: {vuln['severity']}")
                print(f"   Archivo: {vuln['file_path']}")
                print(f"   Linea: {vuln['line_number']}")
                print(f"   Codigo: {vuln['line_content']}")
                print(f"   Tipo: {vuln['type']}")

def main():
    """Función principal"""
    print("=" * 80)
    print("ANALISIS LOCAL DE SEGURIDAD")
    print("=" * 80)

    analyzer = LocalSecurityAnalyzer()

    print("Escaneando directorio actual...")
    vulnerabilities = analyzer.scan_directory('.')

    if not vulnerabilities:
        print("No se encontraron vulnerabilidades")
        return

    # Generar reporte
    report = analyzer.generate_report(vulnerabilities)

    # Imprimir reporte
    analyzer.print_report(report)

    # Guardar reporte
    filename = analyzer.save_report(report)
    print(f"\nReporte guardado en: {filename}")

    # Recomendaciones
    print("\nRECOMENDACIONES:")
    print("1. Revisar vulnerabilidades críticas y altas")
    print("2. Corregir credenciales hardcodeadas")
    print("3. Actualizar algoritmos criptográficos débiles")
    print("4. Deshabilitar debug en producción")
    print("5. Implementar validación de entrada")

if __name__ == "__main__":
    main()
