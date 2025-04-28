
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



