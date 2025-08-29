#!/usr/bin/env python3
"""
Script para verificar el estado real del servicio en Google Cloud.
"""

import requests
import json
from typing import Dict, Any

def check_service_status():
    """Verificar el estado real del servicio."""
    base_url = "https://c4a-alerts-api-f3th7ffaka-uc.a.run.app"

    print("🔍 Verificando Estado Real del Servicio")
    print("=" * 45)
    print(f"🌐 URL: {base_url}")
    print()

    # Verificar diferentes aspectos
    checks = [
        ("Frontend Principal", "/"),
        ("API Health", "/api/v1/health"),
        ("Workers Status", "/api/v1/workers/status"),
        ("Malware Rules", "/api/v1/malware/rules"),
        ("OpenAPI Docs", "/openapi.json"),
        ("Swagger UI", "/docs"),
    ]

    for name, endpoint in checks:
        try:
            url = f"{base_url}{endpoint}"
            response = requests.get(url, timeout=10)

            print(f"📋 {name}:")
            print(f"   🔗 {url}")
            print(f"   📊 Status: {response.status_code}")

            if response.status_code == 200:
                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type:
                    print(f"   ✅ JSON Response (API)")
                    try:
                        data = response.json()
                        print(f"   📦 Data: {json.dumps(data, indent=2)[:200]}...")
                    except:
                        print(f"   📦 Raw: {response.text[:200]}...")
                elif 'text/html' in content_type:
                    print(f"   🌐 HTML Response (Frontend)")
                    if "Sistema No Disponible" in response.text:
                        print(f"   ⚠️  Sistema No Disponible detectado")
                    else:
                        print(f"   ✅ Frontend funcionando")
                else:
                    print(f"   📄 Other: {content_type}")
            else:
                print(f"   ❌ Error: {response.status_code}")

            print()

        except Exception as e:
            print(f"📋 {name}:")
            print(f"   🔗 {url}")
            print(f"   ❌ Error: {e}")
            print()

def show_google_cloud_links():
    """Mostrar enlaces útiles de Google Cloud Console."""
    print("🔗 Enlaces Útiles de Google Cloud Console:")
    print("=" * 45)

    project_id = "c4a-alerts"  # Ajusta según tu proyecto
    service_name = "c4a-alerts-api"
    region = "us-central1"

    links = {
        "Cloud Run Dashboard": f"https://console.cloud.google.com/run?project={project_id}",
        "Servicio Específico": f"https://console.cloud.google.com/run/detail/{region}/{service_name}?project={project_id}",
        "Logs del Servicio": f"https://console.cloud.google.com/run/detail/{region}/{service_name}/logs?project={project_id}",
        "Variables de Entorno": f"https://console.cloud.google.com/run/detail/{region}/{service_name}/revisions?project={project_id}",
        "Tráfico y Métricas": f"https://console.cloud.google.com/run/detail/{region}/{service_name}/metrics?project={project_id}",
        "Configuración": f"https://console.cloud.google.com/run/detail/{region}/{service_name}/edit?project={project_id}",
    }

    for name, url in links.items():
        print(f"🔗 {name}:")
        print(f"   {url}")
        print()

def show_troubleshooting_steps():
    """Mostrar pasos de troubleshooting."""
    print("🔧 Pasos de Troubleshooting:")
    print("=" * 30)

    steps = [
        "1. Ve a Google Cloud Console",
        "2. Navega a Cloud Run",
        "3. Busca tu servicio 'c4a-alerts-api'",
        "4. Verifica el estado (debe estar 'Running')",
        "5. Revisa los logs para errores",
        "6. Verifica variables de entorno",
        "7. Comprueba el tráfico y métricas",
        "8. Si hay errores, revisa la configuración",
    ]

    for step in steps:
        print(f"   {step}")

    print()
    print("⚠️  Posibles Problemas:")
    print("   • Servicio no iniciado")
    print("   • Variables de entorno incorrectas")
    print("   • Errores en el código")
    print("   • Problemas de conectividad")
    print("   • Configuración de rutas incorrecta")

def main():
    """Función principal."""
    print("🚀 Verificador de Estado - Google Cloud Run")
    print("=" * 50)

    try:
        check_service_status()
        show_google_cloud_links()
        show_troubleshooting_steps()

        print("🎯 Recomendación:")
        print("   Ve a Google Cloud Console para ver el estado real")
        print("   del servicio y configurar correctamente las variables")
        print("   de entorno necesarias.")

    except Exception as e:
        print(f"❌ Error durante la verificación: {e}")

if __name__ == "__main__":
    main()
