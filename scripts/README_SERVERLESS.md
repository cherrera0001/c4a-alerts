Oj# C4A Alerts - Serverless Monitoring Platform

## 🎯 **Tu Plataforma de Monitoreo Proactivo**

Una herramienta de **Threat Intelligence** que te mantiene **actualizado y preparado** ante las amenazas, con:

- 📊 **Dashboard en tiempo real** - Panorama completo de amenazas
- 🔔 **Alertas inteligentes** - Notificaciones contextuales y prioritizadas
- 📈 **Análisis de tendencias** - Identificar patrones y evolución
- 🔍 **Búsqueda avanzada** - Encontrar información específica rápidamente
- 📋 **Reportes automáticos** - Resúmenes diarios/semanales
- 🔗 **Integración con OpenCTI** - Conectar con tu ecosistema de CTI

## 🚀 **Arquitectura Serverless**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ GitHub Actions  │───▶│ Cloud Function  │───▶│ Firestore DB    │
│ (Trigger)       │    │ (API)           │    │ (Persistencia)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Vercel Frontend │
                       │ (Web UI)        │
                       └─────────────────┘
```

## 📋 **Características Principales**

### 🔍 **Monitoreo Inteligente**
- **Recolección automática** de múltiples fuentes (CISA, NVD, MITRE, VirusTotal, AbuseIPDB)
- **Deduplicación inteligente** basada en contenido hash
- **Priorización automática** basada en severidad, CVSS, EPSS y confianza
- **Enriquecimiento de datos** con tags automáticos y metadatos

### 📊 **Dashboard Avanzado**
- **Estadísticas en tiempo real** de las últimas 24 horas
- **Filtros dinámicos** por severidad, fuente y tags
- **Búsqueda en tiempo real** en títulos, descripciones y fuentes
- **Visualización de prioridades** con códigos de color

### 🔔 **Alertas Proactivas**
- **Notificaciones contextuales** basadas en severidad
- **Sistema de prioridades** (0-10) calculado automáticamente
- **Tags inteligentes** para categorización automática
- **Historial completo** con timestamps y metadatos

## 🛠️ **Configuración Rápida**

### **Paso 1: Configurar Google Cloud**

```bash
# Instalar Google Cloud CLI
# https://cloud.google.com/sdk/docs/install

# Autenticarse
gcloud auth login

# Crear proyecto
gcloud projects create c4a-alerts-platform --name="C4A Alerts Platform"

# Configurar proyecto
gcloud config set project c4a-alerts-platform

# Habilitar APIs necesarias
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### **Paso 2: Configurar GitHub Secrets**

En tu repositorio GitHub, ve a **Settings > Secrets and variables > Actions** y añade:

```bash
# Google Cloud
GCP_PROJECT_ID=c4a-alerts-platform
GCP_SA_KEY={"type": "service_account", ...}

# Vercel
VERCEL_TOKEN=your-vercel-token
VERCEL_ORG_ID=your-org-id
VERCEL_PROJECT_ID=your-project-id

# Aplicación
SECRET_KEY=your-secret-key
TELEGRAM_BOT_TOKEN=your-telegram-token
SLACK_BOT_TOKEN=your-slack-token
```

### **Paso 3: Deploy Automático**

```bash
# Hacer push a main branch
git push origin main

# El workflow se ejecutará automáticamente:
# 1. Deploy Cloud Functions
# 2. Deploy Frontend en Vercel
# 3. Configurar recolección automática
```

## 📊 **Uso del Dashboard**

### **Panel Principal**
- **Recent Alerts**: Alertas de las últimas 24 horas
- **Critical**: Alertas críticas que requieren atención inmediata
- **High Severity**: Alertas de alta severidad
- **Top Source**: Fuente más activa en los últimos 7 días

### **Filtros y Búsqueda**
- **Search**: Búsqueda en tiempo real en títulos, descripciones y fuentes
- **Severity Filter**: Filtrar por nivel de severidad
- **Source Filter**: Filtrar por fuente de amenazas

### **Lista de Alertas**
- **Priority Score**: Puntuación de prioridad (0-10) calculada automáticamente
- **Severity Badge**: Indicador visual de severidad
- **Metadata**: CVE, CVSS, timestamp, fuente
- **Tags**: Categorización automática

## 🔧 **API Endpoints**

### **Procesar Alerta**
```bash
POST /process_alert
{
  "alert_data": {
    "title": "Nueva vulnerabilidad crítica",
    "description": "Descripción detallada",
    "source": "cisa",
    "severity": "critical",
    "cve_id": "CVE-2024-0001",
    "cvss_score": 9.5
  }
}
```

### **Obtener Alertas**
```bash
POST /process_alert
{
  "action": "get_alerts",
  "filters": {
    "severity": "high",
    "source": "cisa"
  },
  "limit": 50,
  "offset": 0
}
```

### **Dashboard Data**
```bash
POST /process_alert
{
  "action": "get_dashboard"
}
```

### **Estadísticas**
```bash
POST /process_alert
{
  "action": "get_statistics"
}
```

### **Recolectar Alertas**
```bash
POST /collect_alerts
```

## 📈 **Monitoreo y Métricas**

### **Métricas Automáticas**
- **Total de alertas** en la base de datos
- **Alertas del mes** para análisis de tendencias
- **Distribución por severidad** (low, medium, high, critical)
- **Fuentes más activas** en los últimos 7 días

### **Recolección Programada**
- **Automática**: Cada 6 horas via GitHub Actions
- **Manual**: Botón "Collect Alerts" en el dashboard
- **API**: Endpoint para integración con otros sistemas

## 🔗 **Integración con OpenCTI**

### **Próximos Pasos**
1. **Configurar OpenCTI** como fuente de amenazas
2. **Implementar conectores** para MISP y TheHive
3. **Sincronización bidireccional** de datos
4. **Enriquecimiento automático** con contexto de OpenCTI

### **API de Integración**
```python
# Ejemplo de integración con OpenCTI
from opencti import OpenCTIApiClient

client = OpenCTIApiClient("YOUR_OPENCTI_URL", "YOUR_API_KEY")

# Enviar alerta a OpenCTI
client.stix_domain_object.create(
    type="vulnerability",
    name=alert.title,
    description=alert.description,
    confidence=alert.confidence
)
```

## 💰 **Costos Estimados**

| Componente | Costo Mensual | Descripción |
|------------|---------------|-------------|
| **Cloud Functions** | $0-20 | Solo pagas por ejecución |
| **Firestore** | $0-10 | Base de datos NoSQL |
| **Vercel** | $0 | Hosting del frontend |
| **GitHub Actions** | $0 | CI/CD y recolección |

**Total estimado: $0-30/mes** para uso moderado.

## 🚀 **Próximas Mejoras**

### **Fase 2: Producción**
- [ ] **Autenticación** con API keys y JWT
- [ ] **Rate limiting** para protección
- [ ] **Logs estructurados** con Cloud Logging
- [ ] **Monitoreo** con Cloud Monitoring

### **Fase 3: Escalabilidad**
- [ ] **Load balancing** automático
- [ ] **CDN** para mejor rendimiento
- [ ] **Caché** con Redis
- [ ] **Optimización** de costos

### **Fase 4: Integración Avanzada**
- [ ] **OpenCTI** como fuente principal
- [ ] **MISP** para intercambio de IOCs
- [ ] **TheHive** para gestión de casos
- [ ] **Slack/Teams** para notificaciones

## 🆘 **Soporte**

### **Problemas Comunes**

**Error: "Function not found"**
```bash
# Verificar que la función está desplegada
gcloud functions list --region=us-central1
```

**Error: "Permission denied"**
```bash
# Verificar permisos de la cuenta de servicio
gcloud projects get-iam-policy c4a-alerts-platform
```

**Error: "Database connection failed"**
```bash
# Verificar que Firestore está habilitado
gcloud services list --enabled | grep firestore
```

### **Logs y Debugging**
```bash
# Ver logs de Cloud Functions
gcloud functions logs read c4a-alerts-api --region=us-central1

# Ver logs de recolección
gcloud functions logs read c4a-alerts-collector --region=us-central1
```

## 📞 **Contacto**

- **GitHub**: [c4a-alerts](https://github.com/cherrera0001/c4a-alerts)
- **Issues**: Reportar problemas en GitHub Issues
- **Discussions**: Preguntas y sugerencias en GitHub Discussions

---

**¡Tu plataforma de monitoreo está lista para mantenerte al día con las amenazas!** 🚀
