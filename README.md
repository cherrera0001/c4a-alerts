# 🔐 C4A CVE & PoC Alerts — v3.2.1 (2025-05-05)

Sistema automatizado de monitoreo de vulnerabilidades y exploits, con envío de alertas enriquecidas por Telegram y sincronización en tiempo real con Google Sheets para dashboards personalizados en Looker Studio. Ejecutado completamente desde GitHub Actions, sin necesidad de servidores propios.

---

# 🛡️ C4A Alerts

Sistema modular de alerta temprana para amenazas, CVEs, PoCs y noticias de seguridad, automatizado con arquitectura **serverless** y compatible con visualización avanzada vía Google Looker Studio.

## 📁 Estructura del Proyecto

| Ruta                                    | Descripción                                               |
|-----------------------------------------|-----------------------------------------------------------|
| `src/collector.py`                      | Recolector de CVEs y PoCs                                 |
| `src/notifier.py`                       | Envío de mensajes a Telegram                              |
| `src/sync_to_looker.py`                | 🆕 Sincronización con Google Sheets                       |
| `src/secure_storage.py`                 | Historial cifrado en GitHub Gist                          |
| `src/utils.py`                          | Funciones comunes y validaciones                          |
| `src/sources/`                          | Múltiples fuentes (CISA, Reddit, GitHub, CERT, etc.)      |
| `.github/workflows/telegram-alert.yml` | Envío de alertas cada 2 horas                             |
| `.github/workflows/code_quality.yml`   | Análisis de seguridad con Bandit y estilo con Flake8      |
| `.github/workflows/sonarcloud-analysis.yml` | Análisis de código con SonarCloud                    |
| `main.py`                               | Script principal de ejecución                             |
| `monitor_cert_health.py`               | Verificación de salud de feeds RSS                        |
| `requirements.txt`                     | Dependencias necesarias                                   |
| `README.md`                             | Documentación principal                                   |

---

## ✨ Características Nuevas en `v3.2.1`

| Característica                                               | Descripción breve                                                                                      |
|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| ✅ Workload Identity Federation (WIF)                        | Autenticación segura en GCP sin claves estáticas                                                       |
| ✅ Sincronización con Google Sheets                          | Registro automático de alertas en hoja compartida para dashboards Looker                               |
| ✅ Historial cifrado (AES-256-GCM)                           | Persistencia segura y prevención de duplicados                                                         |
| ✅ Modularidad avanzada                                       | Nueva estructura `src/sources/` para integrar más fuentes fácilmente                                    |

---

## 🔐 Autenticación GCP (WIF)

Desde `v3.2.0`, el sistema utiliza **Workload Identity Federation (OIDC)** para autenticarse en GCP sin necesidad de archivos `.json` ni claves estáticas.

### ✅ Secrets requeridos

| Nombre | Uso |
|--------|-----|
| `WIF_PROVIDER` | Workload Identity Provider (`projects/.../providers/github`) |
| `WIF_SERVICE_ACCOUNT` | Email del service account federado (`...@project.iam.gserviceaccount.com`) |
| `LOOKER_SHEET_ID` | ID de la Google Sheet de destino |
| `TELEGRAM_TOKEN` / `CHAT_ID` | Bot de Telegram |
| `ENCRYPTION_KEY` | Cifrado de historial local |
| `GIST_TOKEN` / `GIST_ID` | Persistencia cifrada en GitHub Gist |
| `GHSA_TOKEN`, `REDDIT_*` | Acceso a fuentes externas |

---

## 📊 Visualización en Looker Studio

- El script `sync_to_looker.py` inserta automáticamente las alertas en una **Google Sheet compartida**.
- Looker Studio (Data Studio) puede conectarse a esta hoja para crear dashboards visuales.
- Ideal para analistas SOC, equipos de respuesta, y gestión de riesgos.

---

## 🧪 Pruebas Locales

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar pruebas
python -m unittest discover -s test

