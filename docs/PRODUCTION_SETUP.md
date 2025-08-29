# 🚀 Configuración de Producción - C4A Alerts Bot

## 📋 Variables de Entorno para Producción

### 🔑 Variables Requeridas

| Variable | Desarrollo Local | Producción | Descripción |
|----------|------------------|------------|-------------|
| `TELEGRAM_TOKEN` | `YOUR_TELEGRAM_BOT_TOKEN_HERE` | `YOUR_TELEGRAM_BOT_TOKEN_HERE` | Token del bot (mismo) |
| `ADMIN_USER_ID` | `551008154` | `551008154` | Tu ID (mismo) |
| `ADMIN_CHAT_ID` | `551008154` | `551008154` | Chat para notificaciones (mismo) |
| `READ_ONLY_MODE` | `true` | `true` | Modo solo lectura (mismo) |
| `C4A_API_URL` | `http://localhost:8000` | `https://tu-dominio.com/api` | **URL de la API (cambia)** |
| `LOG_LEVEL` | `INFO` | `INFO` | Nivel de logs (mismo) |

### 🌐 Variables Opcionales para Producción

| Variable | Descripción | Ejemplo |
|----------|-------------|---------|
| `WEBHOOK_URL` | URL del webhook para Telegram | `https://tu-dominio.com/telegram_webhook` |
| `WEBHOOK_SECRET` | Secreto para validar webhooks | `mi_secreto_super_seguro_123` |

## 🔧 Configuración en GitHub Secrets

### Paso 1: Ir a GitHub Secrets
1. Ve a tu repositorio en GitHub
2. Settings > Secrets and variables > Actions
3. Click "New repository secret"

### Paso 2: Agregar Variables

```bash
# Variables principales (igual que local)
TELEGRAM_TOKEN=YOUR_TELEGRAM_BOT_TOKEN_HERE
ADMIN_USER_ID=551008154
ADMIN_CHAT_ID=551008154
READ_ONLY_MODE=true
LOG_LEVEL=INFO

# Variables de producción (cambian)
C4A_API_URL=https://tu-dominio.com/api
WEBHOOK_URL=https://tu-dominio.com/telegram_webhook
WEBHOOK_SECRET=mi_secreto_super_seguro_123
```

## 🚀 Opciones de Despliegue

### Opción 1: GitHub Actions (Recomendado)
- Automático al hacer push
- Usa los secrets configurados
- Despliegue continuo

### Opción 2: Vercel
- Despliegue automático
- SSL gratuito
- CDN global

### Opción 3: Heroku
- Fácil de configurar
- Escalable
- Base de datos incluida

### Opción 4: Google Cloud Functions
- Serverless
- Escalado automático
- Integración con Google Cloud

## 📊 Diferencias Clave

### 🔄 Lo que NO cambia:
- `TELEGRAM_TOKEN` - Mismo bot
- `ADMIN_USER_ID` - Tu ID
- `ADMIN_CHAT_ID` - Tu chat
- `READ_ONLY_MODE` - Misma funcionalidad
- `LOG_LEVEL` - Mismo nivel

### 🔄 Lo que SÍ cambia:
- `C4A_API_URL` - De localhost a dominio público
- `WEBHOOK_URL` - URL pública para Telegram
- `WEBHOOK_SECRET` - Seguridad adicional

## 🛡️ Seguridad en Producción

### ✅ Configuraciones de Seguridad:
- HTTPS obligatorio
- Webhook secret para validación
- Rate limiting
- Logs de auditoría
- Monitoreo de acceso

### ⚠️ Consideraciones:
- Usar dominios confiables
- Configurar SSL/TLS
- Monitorear logs
- Backup de configuración

## 🎯 Configuración Rápida

### Script Automático:
```bash
python scripts/setup_github_secrets.py
```

### Manual:
1. Copiar variables de `.env` local
2. Cambiar `C4A_API_URL` a tu dominio
3. Agregar `WEBHOOK_URL` y `WEBHOOK_SECRET`
4. Configurar en GitHub Secrets

## 📞 Soporte

Para problemas de configuración:
- Revisar logs de GitHub Actions
- Verificar variables de entorno
- Comprobar conectividad de red
- Validar permisos del bot
