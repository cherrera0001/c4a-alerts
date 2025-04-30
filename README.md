
# 🔐 C4A CVE & PoC Alerts — v3.1.0

Sistema automatizado de monitoreo de vulnerabilidades y exploits, con envío de alertas enriquecidas por Telegram. Ejecutado completamente desde GitHub Actions, sin necesidad de servidores propios.

---

# 🛡️ C4A Alerts

Sistema modular de alerta temprana para amenazas, CVEs, PoCs y noticias de seguridad, automatizado en GitHub Actions.

## 📁 Estructura del Proyecto

| Ruta                                  | Descripción                                               |
|---------------------------------------|-----------------------------------------------------------|
| `src/collector.py`                    | Recolector de CVEs y PoCs                                |
| `src/notifier.py`                     | Envío de mensajes a Telegram                             |
| `src/secure_storage.py`               | Historial cifrado en GitHub Gist                         |
| `src/utils.py`                        | Funciones comunes y validaciones                         |
| `src/sources/reddit.py`              | Fuente: Reddit                                           |
| `src/sources/exploitdb.py`           | Fuente: Exploit-DB                                       |
| `src/sources/threatfeeds.py`         | Fuente: Feeds generales (ThreatPost, HackerNews, etc.)   |
| `src/sources/cert.py`                | Fuente: CERTs nacionales e internacionales               |
| `src/sources/cisa.py`                | Fuente: CISA (EE.UU.)                                    |
| `src/sources/mitre.py`               | Fuente: MITRE ATT&CK                                     |
| `src/sources/stepsecurity.py`        | Fuente: StepSecurity                                     |
| `src/sources/github_advisories.py`   | 🆕 GitHub Security Advisories                            |
| `test/`                               | Pruebas unitarias                                        |
| `.github/workflows/telegram-alert.yml` | Envío de alertas (cada 2 horas)                          |
| `.github/workflows/code_quality.yml` | Análisis de calidad (flake8, bandit)                     |
| `.github/workflows/sonarcloud-analysis.yml` | Análisis de bugs y deuda técnica                 |
| `.github/workflows/health_check.yml` | Monitoreo de salud de fuentes CERT                       |
| `main.py`                             | Script principal de ejecución                            |
| `monitor_cert_health.py`             | Verificación de salud de los feeds                       |
| `requirements.txt`                   | Dependencias necesarias                                  |
| `.flake8`                             | Reglas de estilo para flake8                             |
| `.sonarcloud.properties`             | Configuración para SonarCloud                            |
| `README.md`                           | Documentación principal                                  |



## ✨ Características Nuevas en `v3.1.0`

| Característica                                               | Descripción breve                                                                                      |
|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| ✅ Historial cifrado (AES-256-GCM)                           | Se evita el reenvío de alertas duplicadas mediante control persistente y seguro.                       |
| ✅ GitHub Security Advisories                                | Nueva fuente integrada vía GraphQL para CVEs y alertas oficiales desde GitHub.                         |
| ✅ Filtrado por keywords críticas                            | Detección inteligente de amenazas con palabras como `RCE`, `0day`, `bypass`, `exploit`, etc.            |
| ✅ Monitoreo de CERTs y CISA                                 | Incluye alertas de múltiples fuentes nacionales e internacionales de ciberseguridad.                   |
| ✅ Sistema modular                                           | Arquitectura lista para escalar: nuevas fuentes se integran con mínimo esfuerzo.                       |
| ✅ Análisis de seguridad y calidad                           | Bandit (vulnerabilidades), Flake8 (estilo), SonarCloud (bugs, deuda técnica).                          |
| ✅ 100% Automatizado en GitHub Actions                       | No requiere VPS ni servidores, se ejecuta de forma serverless bajo eventos programados (`cron`).        |

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

## ☁️ ¿Por qué `C4A-Alerts` es Serverless?

| Concepto                             | ¿C4A-Alerts cumple? ✅ | Justificación técnica                                                                                                                                     |
|--------------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **No gestión directa de servidores** | ✅                     | Tú no administras servidores físicos ni VPS: el bot corre en **GitHub Actions**, que es una plataforma CI/CD administrada.                              |
| **Pago por uso / gratuito**          | ✅                     | GitHub Actions usa **tiers gratuitos o por uso**, y ejecuta tu código solo cuando ocurre un trigger (`push`, `schedule`, etc). **No pagas** por servidor. |
| **Escala automática (limitada)**     | ✅                     | GitHub ejecuta workflows bajo demanda. Aunque tiene límites, **escala a múltiples ejecuciones concurrentes** sin que debas escalar servidores.           |
| **Infraestructura abstracta**        | ✅                     | No necesitas instalar SO, parchear, ni monitorear hardware. Solo defines el flujo (`.yml`) y el script (`python`) que debe ejecutarse.                  |
| **Event-driven (disparado por eventos)** | ✅                 | El sistema corre automáticamente por **horarios programados** (`cron`) o por eventos como `push`. Modelo clásico **serverless**: ejecución bajo demanda. |

