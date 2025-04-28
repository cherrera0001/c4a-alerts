
# 🔐 C4A CVE & PoC Alerts — v3.0.1

Sistema automatizado de monitoreo de vulnerabilidades y exploits, con envío de alertas enriquecidas por Telegram. Ejecutado completamente desde GitHub Actions, sin necesidad de servidores propios.

---

# 🛡️ C4A Alerts

Sistema modular de alerta temprana para amenazas, CVEs, PoCs y noticias de seguridad, automatizado en GitHub Actions.

---

## 🚀 Estructura del Proyecto

```plaintext
c4a-alerts/
├── src/
│   ├── collector.py         # Recolector de CVEs y PoCs
│   ├── notifier.py          # Envío de mensajes a Telegram
│   ├── secure_storage.py    # Cifrado AES + almacenamiento en GitHub Gist
│   ├── utils.py             # Funciones comunes (Markdown, validación)
│   └── sources/             # Múltiples fuentes externas
│       ├── reddit.py
│       ├── exploitdb.py
│       ├── threatfeeds.py
│       ├── cert.py
│       ├── cisa.py
│       ├── mitre.py
│       ├── stepsecurity.py
├── test/                    # Pruebas unitarias
├── .github/
│   └── workflows/
│       ├── telegram-alert.yml      # Envío de alertas (cada 5 min)
│       ├── code_quality.yml        # Análisis estático (flake8, bandit)
│       ├── sonarcloud-analysis.yml # Análisis de bugs y calidad en SonarCloud
│       ├── health_check.yml        # Monitoreo de estado de feeds CERT
├── main.py                  # Script principal de ejecución
├── monitor_cert_health.py    # Script para verificación de fuentes
├── requirements.txt         # Dependencias necesarias
├── .flake8                   # Reglas de estilo
├── .sonarcloud.properties    # Configuración de SonarCloud
└── README.md

---

✨ Características Nuevas en v3.0.1

🔐 Historial cifrado en Gist con AES-256-GCM

✅ Control de duplicados: no se reenvían CVEs/PoCs ya alertados

🧹 Modular: integración de múltiples fuentes como Reddit y Exploit-DB

🧪 Sistema de testing automatizado

🚀 Dos workflows separados: alert y test



---

🗕️ Automatización en GitHub Actions

📤 telegram-alert.yml

Se ejecuta cada 5 minutos:

1. Recupera CVEs, PoCs y Noticias de Amenazas


2. Filtra por severidad y relevancia


3. Verifica duplicados y estado


4. Envía mensajes nuevos a Telegram



🧪 test.yml

Corre automáticamente en cada push o pull request:

Ejecuta unittest sobre los módulos de test/

Valida correcto funcionamiento de módulos principales



---

🔐 Secrets Requeridos

> ⚠️ Todos los secrets deben estar configurados en Settings > Secrets and variables > Actions




---

🧪 Pruebas Locales

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar pruebas unitarias
python -m unittest discover -s test


---

💡 Fuentes Integradas

🔍 https://cve.circl.lu/api/last (CVEs recientes)

📂 nomi-sec/PoC-in-GitHub (PoCs en GitHub)

🗣️ Reddit r/netsec

🪨 Exploit-DB (scraping controlado)

📰 Threat Intelligence Feeds (HackerNews, ThreatPost, etc.)



---

🛡️ Seguridad

Cifrado de historial con cryptography y AES-GCM

Tokens seguros vía GitHub Secrets

Validaciones estrictas de entradas y outputs

Cumplimiento básico de OWASP ASVS en almacenamiento y comunicación



---

📊 Métricas CI/CD

⏱️ Tiempo de ejecución (run duration)

❌ Logs de errores HTTP

📬 Conteo de mensajes enviados exitosamente

🗂️ Historial persistente de CVEs/PoCs encriptados



---

🌐 Mantenido por @cherrera0001


---
📊 Diagrama de Flujo Simplificado

+----------------+         +-------------------------+          +--------------------+
| GitHub Actions | --GET-> | Múltiples fuentes CVE/PoC | --POST-> | Telegram Bot API   |
| (cada 5 min)   |         | CIRCL / GitHub / Reddit |          | Chat/Grupo/Canal   |
+----------------+         +-------------------------+          +--------------------+


---

> ❓ ¿Quieres contribuir, clonar o adaptarlo? ¡Forkea el repo, ajusta los secrets y comienza a proteger tu mundo!




