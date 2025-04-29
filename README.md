
# 🔐 C4A CVE & PoC Alerts — v3.1.0

Sistema automatizado de monitoreo de vulnerabilidades y exploits, con envío de alertas enriquecidas por Telegram. Ejecutado completamente desde GitHub Actions, sin necesidad de servidores propios.

---

# 🛡️ C4A Alerts

Sistema modular de alerta temprana para amenazas, CVEs, PoCs y noticias de seguridad, automatizado en GitHub Actions.

---

c4a-alerts/
├── src/
│   ├── collector.py            # Recolector de CVEs y PoCs
│   ├── notifier.py             # Envío de mensajes a Telegram
│   ├── secure_storage.py       # Historial cifrado en GitHub Gist
│   ├── utils.py                # Funciones comunes y validaciones
│   └── sources/                # Integraciones de datos
│       ├── reddit.py
│       ├── exploitdb.py
│       ├── threatfeeds.py
│       ├── cert.py
│       ├── cisa.py
│       ├── mitre.py
│       ├── stepsecurity.py
│       ├── github_advisories.py  # 🆕 GitHub Security Advisories
├── test/                        # Pruebas unitarias
├── .github/
│   └── workflows/
│       ├── telegram-alert.yml    # Envío de alertas (cada 2 horas)
│       ├── code_quality.yml      # Análisis de calidad (flake8, bandit)
│       ├── sonarcloud-analysis.yml  # Análisis de bugs y deuda técnica
│       ├── health_check.yml      # Monitoreo de salud de fuentes CERT
├── main.py                      # Ejecución principal
├── monitor_cert_health.py        # Verificación de salud de feeds
├── requirements.txt              # Dependencias necesarias
├── .flake8                       # Reglas de estilo
├── .sonarcloud.properties        # Configuración SonarCloud
└── README.md



---

✨ Características Nuevas (v3.1.0)

✅ Control de duplicados con historial cifrado (AES-256-GCM)
✅ Integración con GitHub Security Advisories
✅ Filtrado inteligente por palabras clave críticas
✅ Monitoreo de feeds nacionales e internacionales (CERTs, CISA, etc.)
✅ Sistema modular y escalable (fuentes fáciles de añadir)
✅ Análisis de seguridad (Bandit) y calidad de código (Flake8, SonarCloud)
✅ Automatización completa en GitHub Actions


---

🗕️ Automatización en GitHub Actions

📤 telegram-alert.yml

    Recoge amenazas de múltiples fuentes

    Filtra alertas críticas

    Envía notificaciones por Telegram

🛡️ code_quality.yml

    Ejecuta análisis de seguridad con Bandit

    Verifica estilo de código con Flake8

📊 sonarcloud-analysis.yml

    Escanea el proyecto en SonarCloud para detectar bugs, code smells y vulnerabilidades

🔍 health_check.yml

    Verifica disponibilidad y estado de todos los feeds RSS/JSON integrados


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

-----



![test](https://github.com/user-attachments/assets/af972a8b-a743-438c-b37e-261b142716e8)
