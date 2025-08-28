#!/usr/bin/env python3
"""
Test script para verificar la integración con MISP CSIRT
"""

import os
import sys
import json
from datetime import datetime

# Agregar el directorio cloud-function al path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'cloud-function'))

def test_misp_csirt_integration():
    """Probar la integración con MISP CSIRT"""

    print("🔍 Probando integración con MISP CSIRT...")
    print("=" * 50)

    # Verificar variables de entorno
    base_url = os.getenv('ANCI_BASE_URL', 'https://apimisp.csirt.gob.cl')
    username = os.getenv('ANCI_USERNAME', 'crherrera@c4a.cl')
    password = os.getenv('ANCI_PASSWORD', '')

    print(f"📊 Configuración:")
    print(f"   Base URL: {base_url}")
    print(f"   Username: {username}")
    print(f"   Password: {'*' * len(password) if password else 'NO CONFIGURADO'}")
    print()

    if not password:
        print("❌ Error: ANCI_PASSWORD no está configurado")
        print("   Configura la variable de entorno ANCI_PASSWORD")
        return False

    try:
        # Importar el collector
        from collectors.misp_csirt import misp_csirt_collector

        print("✅ Collector MISP CSIRT importado correctamente")

        # Probar autenticación
        print("\n🔐 Probando autenticación...")
        token = misp_csirt_collector._get_auth_token()
        if token:
            print("✅ Autenticación exitosa")
            print(f"   Token: {token[:20]}...")
        else:
            print("❌ Error en autenticación")
            return False

        # Probar recolección de IPs
        print("\n🌐 Probando recolección de IPs...")
        ip_alerts = misp_csirt_collector.collect_ip_threats(days_back=1)
        print(f"   IPs recolectadas: {len(ip_alerts)}")

        # Probar recolección de dominios
        print("\n🏷️ Probando recolección de dominios...")
        domain_alerts = misp_csirt_collector.collect_suspicious_domains(days_back=1)
        print(f"   Dominios recolectados: {len(domain_alerts)}")

        # Probar recolección de URLs
        print("\n🔗 Probando recolección de URLs...")
        url_alerts = misp_csirt_collector.collect_malicious_urls(days_back=1)
        print(f"   URLs recolectadas: {len(url_alerts)}")

        # Probar recolección de APTs
        print("\n👥 Probando recolección de APTs...")
        apt_alerts = misp_csirt_collector.collect_apts()
        print(f"   APTs recolectados: {len(apt_alerts)}")

        # Probar recolección completa
        print("\n📡 Probando recolección completa...")
        all_alerts = misp_csirt_collector.collect_all(days_back=1)
        print(f"   Total de alertas: {len(all_alerts)}")

        # Mostrar ejemplo de alerta
        if all_alerts:
            print("\n📋 Ejemplo de alerta:")
            example = all_alerts[0]
            print(f"   Título: {example.get('title')}")
            print(f"   Fuente: {example.get('source')}")
            print(f"   Severidad: {example.get('severity')}")
            print(f"   Tags: {', '.join(example.get('tags', []))}")

        print("\n✅ Integración MISP CSIRT funcionando correctamente!")
        return True

    except ImportError as e:
        print(f"❌ Error importando collector: {e}")
        return False
    except Exception as e:
        print(f"❌ Error en la integración: {e}")
        return False

if __name__ == "__main__":
    success = test_misp_csirt_integration()
    sys.exit(0 if success else 1)
