# 🔐 C4A CVE & PoC Alerts — v2.0.0

Sistema automatizado de monitoreo de vulnerabilidades y exploits, con envío de alertas enriquecidas por Telegram. Ejecutado completamente desde GitHub Actions, sin necesidad de servidores propios.

---

## ⚙️ Arquitectura del Proyecto

```plaintext
c4a-alerts/
├── src/
│   ├── collector.py          # Recolector de CVEs y PoCs
│   ├── notifier.py           # Envío de mensajes a Telegram
│   ├── secure_storage.py     # Cifrado AES + almacenamiento en GitHub Gist
│   ├── utils.py              # Funciones comunes (Markdown, validación)
│   └── sources/              # Múltiples fuentes externas
│       ├── reddit.py
│       └── exploitdb.py
├── test/                     # Pruebas unitarias
│   └── test_*.py
├── .github/
│   └── workflows/
│       ├── telegram-alert.yml  # Envío de alertas CVE/PoC (cada 5 min)
│       └── test.yml            # CI para validación de tests
├── main.py                  # Script principal de ejecución
├── requirements.txt         # Librerías necesarias
└── README.md
```

---

## ✨ Características Nuevas en v2.0.0

- 🔐 Historial cifrado en Gist con AES-256-GCM
- ✅ Control de duplicados: no se reenvían CVEs/PoCs ya alertados
- 🧹 Modular: integración de múltiples fuentes como Reddit y Exploit-DB
- 🧪 Sistema de testing automatizado
- 🚀 Dos workflows separados: `alert` y `test`

---

## 🗕️ Automatización en GitHub Actions

### 📤 `telegram-alert.yml`
Se ejecuta cada 5 minutos:

1. Recupera CVEs y PoCs
2. Filtra por CVSS ≥ 7.0
3. Valida enlaces y estado
4. Verifica si ya se alertó
5. Envía mensajes nuevos a Telegram

### 🧪 `test.yml`
Corre automáticamente en cada push o pull request sobre `main` y ejecuta:

- `unittest` sobre los módulos de `test/`

---

## 🔐 Secrets Requeridos

| Nombre           | Descripción                                              |
|------------------|----------------------------------------------------------|
| `TELEGRAM_TOKEN` | Token del bot creado con @BotFather                      |
| `CHAT_ID`        | ID del grupo o canal de Telegram donde alertar          |
| `GIST_ID`        | ID del Gist donde se guarda el historial cifrado        |
| `GIST_TOKEN`     | Token personal de GitHub con permisos `gist`            |
| `ENCRYPTION_KEY` | Clave AES-256 en base64 (genera con `os.urandom`)       |

> ⚠️ Todos los secrets deben estar configurados en `Settings > Secrets and variables > Actions`

---

## 🧪 Pruebas Locales

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar pruebas unitarias
python -m unittest discover -s test
```

---

## 💡 Fuentes Integradas

- 🔍 [https://cve.circl.lu/api/last](https://cve.circl.lu/api/last) (CVEs recientes)
- 📂 `nomi-sec/PoC-in-GitHub` (PoCs en GitHub)
- 🗣️ [Reddit r/netsec](https://www.reddit.com/r/netsec/new.json)
- 🪨 [https://exploit-db.com](https://exploit-db.com) (via scraping)

---

## 🛡️ Seguridad

- Cifrado de historial con `cryptography` y AES-GCM
- Tokens seguros vía GitHub Secrets
- Filtrado estricto con validaciones de formato y enlaces HTTPS
- Cumplimiento básico de OWASP ASVS: autenticación, almacenamiento seguro, sanitización de inputs

---

## 📊 Métricas CI/CD

- ⏱️ Tiempo de ejecución (`run duration`)
- ❌ Logs de errores HTTP
- 📬 Conteo de mensajes enviados
- 🗂️ Historial persistente de CVEs/PoCs encriptados

---

## 🌐 Mantenido por [@cherrera0001](https://github.com/cherrera0001)

---

## 📊 Diagrama de Flujo Simplificado

```plaintext
+----------------+         +-------------------------+          +--------------------+
| GitHub Actions | --GET-> | Múltiples fuentes CVE/PoC | --POST-> | Telegram Bot API   |
| (cada 5 min)   |         | CIRCL / GitHub / Reddit |          | Chat/Grupo/Canal   |
+----------------+         +-------------------------+          +--------------------+
```

---

❓ ¿Quieres contribuir, clonar o adaptarlo? Forkea el repo, ajusta los secrets y ¡listo! ✨

