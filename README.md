## ⚙️ Arquitectura del proyecto

# 🔊 C4A CVE & PoC Alerts (v2)

Este proyecto permite monitorear vulnerabilidades críticas (CVEs) y sus pruebas de concepto (PoCs), enviando alertas automáticas a Telegram usando GitHub Actions, sin necesidad de servidores propios.

---

## ✨ Características Principales

- ⚡ Recupera CVEs recientes desde la API de [CIRCL](https://cve.circl.lu/api/last)
- 🔍 Busca PoCs desde GitHub (nomi-sec/PoC-in-GitHub), con fallback a varias rutas
- ✉️ Envía alertas enriquecidas por bot de Telegram en formato MarkdownV2
- 🚀 Ejecutado completamente desde GitHub Actions (CI/CD serverless)
- ✅ Filtrado de CVEs por año actual y CVSS >= 7.0 (Alta o Crítica)
- 🌎 Preparado para grupos/canales Telegram y reutilizable por otros equipos

---

## 📅 Automatización en GitHub Actions

El flujo `telegram-alert.yml` se ejecuta cada 5 minutos y:

1. Carga variables seguras desde `secrets`
2. Ejecuta `main.py`
3. Envía alertas de nuevos CVEs y PoCs a Telegram si se detectan cambios

---

## 🔑 Variables Requeridas (GitHub Secrets)

- `TELEGRAM_TOKEN`: Token generado con @BotFather
- `CHAT_ID`: ID de usuario, grupo o canal a notificar

Para obtener el `chat_id`, usa:

```bash
curl "https://api.telegram.org/bot<TELEGRAM_TOKEN>/getUpdates"
```

Y extrae el `chat.id` desde el JSON devuelto.

---

## 💡 Tecnologías Usadas

- Python 3.10+
- GitHub Actions (cron + dispatch)
- Telegram Bot API
- MarkdownV2
- dotenv / secrets

---

## 📊 Futuras Mejoras

- 🔀 Integrar Exploit-DB, Vulners API como fuentes alternativas
- 🔀 Cache local y control de duplicados
- 🌐 Dashboard simple con Flask
- 🤖 Integración de GPT para validación inteligente de CVEs

---

## 🌟 Métricas CI/CD Sugeridas (en GitHub Actions)

- **Time to run**: tiempo de ejecución del job (ver en *Actions > Usage metrics*)
- **Errores HTTP**: logeados en consola, podrían exportarse a Prometheus o Log Analytics (a futuro)
- **Envíos efectivos**: contar mensajes exitosos enviados (ya logeado)

Puedes consultar y extender estas métricas accediendo a:

```
Actions > Performance Metrics
```

---

## 🌐 Proyecto mantenido por: [@cherrera0001](https://github.com/cherrera0001)


### Diagrama simplificado

```plaintext
+------------------+            +------------------+             +--------------------+
| GitHub Actions   | --GET-->   |  CVE & PoC Feeds |  --POST-->  | Telegram Bot (API) |
| (cada 5 min)    |            | (JSON APIs)      |             | Mensaje recibido   |
+------------------+            +------------------+             +--------------------+
