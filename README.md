## ⚙️ Arquitectura del proyecto

C4A Telegram Alerts es un microservicio **sin servidor** que corre completamente en **GitHub Actions** y envía alertas de ciberseguridad a **Telegram**, sin requerir entorno local, servidores dedicados ni infraestructura en la nube.

### ¿Cómo funciona?

1. **Sin entorno local**: No necesitas instalar nada en tu PC. Todo el procesamiento se realiza en los runners gratuitos de GitHub.
2. **GitHub Actions como motor**: El código se ejecuta automáticamente en la nube cada cierto tiempo (o bajo demanda).
3. **Consulta CVEs y PoCs**:
   - CVEs desde la API de CIRCL (`https://cve.circl.lu/api/last`)
   - PoCs desde GitHub (`nomi-sec/PoC-in-GitHub`)
4. **Escapa el contenido para Telegram** usando `MarkdownV2`
5. **Entrega los mensajes** a tu bot personal o grupal en Telegram

### Seguridad
- Las credenciales (`TELEGRAM_TOKEN`, `CHAT_ID`) se gestionan como secretos de GitHub (`Settings > Secrets`).
- No se expone información sensible en el repositorio.
- Los mensajes están protegidos por un escape automático para evitar errores de formato.

### Diagrama simplificado

```plaintext
+------------------+            +------------------+             +--------------------+
| GitHub Actions   | --GET-->   |  CVE & PoC Feeds |  --POST-->  | Telegram Bot (API) |
| (cada 5 min)    |            | (JSON APIs)      |             | Mensaje recibido   |
+------------------+            +------------------+             +--------------------+
