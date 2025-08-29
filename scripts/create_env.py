#!/usr/bin/env python3
"""
Script para crear el archivo .env con la configuración correcta
"""

import os
from pathlib import Path

def create_env_file():
    """Crear archivo .env con la configuración de Telegram"""

    env_content = """# C4A Alerts - Configuración de Variables de Entorno
# Copia este archivo como .env y configura tus valores

# =============================================================================
# CONFIGURACIÓN DE TELEGRAM
# =============================================================================
TELEGRAM_TOKEN=YOUR_TELEGRAM_BOT_TOKEN_HERE
CHAT_ID=551008154

# =============================================================================
# CONFIGURACIÓN DE SLACK (OPCIONAL)
# =============================================================================
SLACK_WEBHOOK_URL=your_slack_webhook_url_here
SLACK_CHANNEL=#alerts

# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS (OPCIONAL)
# =============================================================================
DATABASE_URL=sqlite:///./c4a_alerts.db

# =============================================================================
# CONFIGURACIÓN DE API
# =============================================================================
API_KEY=your_api_key_here
ENVIRONMENT=development

# =============================================================================
# CONFIGURACIÓN DE COLECTORES
# =============================================================================
MISP_URL=your_misp_url_here
MISP_API_KEY=your_misp_api_key_here
CSIRT_URL=your_csirt_url_here
CSIRT_API_KEY=your_csirt_api_key_here

# =============================================================================
# CONFIGURACIÓN DE ANÁLISIS DE SEGURIDAD
# =============================================================================
FLUID_ATTACKS_TOKEN=eyJhbGciOiJSUzUxMiJ9.eyJjaXBoZXJ0ZXh0IjoibWV3NWRiNXFxX2xVSV9ONHM1NFlSdnZPYnNDcG91MmloaFZXNlRPcnFXMnF5UmVrVVB4c0RqVldKZ0c4cXhWTnVScVNTSF9xbzFNSTBXSm8zZUx4UUktZUhZS0tPNXZIbDJlbUstLXBfR2haQ0N0M0JPcUlHQ3dlYXNQUUZORFBMTmZxSTJReDhsdklOZTRpWXBtcmRVZ3JXR2hBQmNocnVhNU9pb0c1d3lyOHNOWlVyd1daT1h2OWc4QmxfNDlIcDJZeUoxQjFvam5CTEtnTEo1bURocmJZdjFxZWxtVGRSNndwX2VIX2Nsb2JaNXpqRGx0MmhBIiwiZW5jcnlwdGVkX2tleSI6IjFiMHo0OGM3c3pGWmEwbkliOC1fY05KZmxRX2VQRkFxTjVMYlNfNzUxMGciLCJleHAiOjE3NTkyMDQ4MDAsImhlYWRlciI6eyJpdiI6InVPc2hkWVA2bmlxTko3bnoiLCJ0YWciOiJldUgta00zcFlYUmd1UHJ5d1JoRHN3In0sIml2IjoiaXMtZVJobS1XWGd2TkRJWiIsInByb3RlY3RlZCI6ImV5SmhiR2NpT2lKQk1qVTJSME5OUzFjaUxDSmxibU1pT2lKQk1qVTJSME5OSW4wIiwic3ViIjoiYXBpX3Rva2VuIiwidGFnIjoiSUJ2cWhxTFUwYzRiVE5xTG9tYm1uZyJ9.MXcphri7Z30BqKhvNQgkV6VfU7UDjuiOb77d46z4OdxhJ7-psVM-5uuYUrM3eq0rfdpXoEYUEorMWC-qxqd96APsv-mL3bAVoHoKBm3tbOt5KRPoeQOyvytuR9z3SWmgLpzm71nzPgDkBT-VoZs7DT51JgLVEX-v8_IQ1tImbzO3EODYIivlR57zuSHCuFtVPUB0IeI2POhk4EygtAAGcmbHpRCVkjFfrTDMK_3Ik8cqtHiSQBTfVxeUG-QTXc1d8VEWYjOVU22G-EAQoIPNiGam9fy5c0lx-gr2qp9B2heBusjdwdEoii-fecWRyBGcpHvLnmE0La5D_XwSGCQr3w
"""

    env_path = Path('.env')

    try:
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(env_content)

        print("✅ Archivo .env creado exitosamente!")
        print(f"📁 Ubicación: {env_path.absolute()}")
        print("\n📋 Contenido del archivo:")
        print("=" * 50)
        print(env_content)
        print("=" * 50)

        return True

    except Exception as e:
        print(f"❌ Error creando archivo .env: {e}")
        return False

def main():
    """Función principal"""
    print("=" * 50)
    print("📝 CREAR ARCHIVO .ENV")
    print("=" * 50)

    if create_env_file():
        print("\n🎉 ¡Configuración completada!")
        print("💡 Ahora puedes ejecutar: python scripts/validate_telegram.py")
    else:
        print("\n❌ Error en la configuración")

if __name__ == "__main__":
    main()
