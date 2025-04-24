# 📦 CHANGELOG — C4A Alerts

Todas las actualizaciones importantes de este proyecto se documentan aquí.

---

## [2.0.0] - 2025-04-24
### 🚀 Nueva versión mayor — C4A Alerts v2
- 🔐 Almacenamiento cifrado de historial en GitHub Gist (AES-256-GCM)
- ✅ Control de duplicados de alertas de CVEs y PoCs
- 🔗 Nuevas fuentes: Reddit (`/r/netsec`) y Exploit-DB (scraping)
- 🧪 Sistema de pruebas unitarias con `unittest`
- 🧩 Modularización completa del código (`src/`, `test/`, `utils`)
- 📤 Alertas por Telegram optimizadas con MarkdownV2
- 🛠️ Workflows GitHub separados para `alert` y `test`
- 📄 Documentación (README.md) y Licencia (MIT) actualizadas

---

## [1.0.1] - 2025-04-23
### Primera versión funcional
- Recuperación de CVEs recientes desde CIRCL
- PoCs desde GitHub (nomi-sec)
- Envío de mensajes a Telegram cada 5 minutos
- Automatización con GitHub Actions
