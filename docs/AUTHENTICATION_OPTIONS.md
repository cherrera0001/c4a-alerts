# Google Cloud Authentication Options

## 🎯 **Alternativas sin Navegador**

### **Opción 1: Service Account Key (RECOMENDADA)**

#### **Crear Service Account**
```bash
# Crear service account
gcloud iam service-accounts create c4a-alerts-sa \
    --display-name="C4A Alerts Service Account" \
    --description="Service account for C4A Alerts platform"

# Asignar roles necesarios
gcloud projects add-iam-policy-binding c4a-alerts-platform \
    --member="serviceAccount:c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com" \
    --role="roles/cloudfunctions.developer"

gcloud projects add-iam-policy-binding c4a-alerts-platform \
    --member="serviceAccount:c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com" \
    --role="roles/datastore.user"

gcloud projects add-iam-policy-binding c4a-alerts-platform \
    --member="serviceAccount:c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com" \
    --role="roles/cloudbuild.builds.builder"

# Crear y descargar la clave
gcloud iam service-accounts keys create ~/c4a-alerts-key.json \
    --iam-account=c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com
```

#### **Usar la Service Account**
```bash
# Autenticarse con la service account
gcloud auth activate-service-account --key-file=~/c4a-alerts-key.json

# Verificar autenticación
gcloud auth list
```

#### **Para GitHub Actions**
```bash
# En GitHub Secrets, añadir:
GCP_SA_KEY={"type": "service_account", "project_id": "c4a-alerts-platform", ...}

# En el workflow:
- name: Authenticate to Google Cloud
  uses: google-github-actions/auth@v1
  with:
    credentials_json: ${{ secrets.GCP_SA_KEY }}
```

---

### **Opción 2: Application Default Credentials (ADC)**

#### **Configurar ADC**
```bash
# Configurar credenciales por defecto
gcloud auth application-default login

# O usar service account
gcloud auth application-default set-quota-project c4a-alerts-platform
```

#### **Usar en Código**
```python
from google.cloud import firestore
from google.auth import default

# Usar credenciales por defecto automáticamente
credentials, project = default()
db = firestore.Client(project=project)
```

---

### **Opción 3: Workload Identity Federation (Avanzada)**

#### **Configurar WIF**
```bash
# Crear pool de identidades
gcloud iam workload-identity-pools create "github-actions-pool" \
    --location="global" \
    --display-name="GitHub Actions Pool"

# Crear provider
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
    --workload-identity-pool="github-actions-pool" \
    --location="global" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository"

# Permitir autenticación
gcloud iam service-accounts add-iam-policy-binding \
    "c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/attribute.repository/cherrera0001/c4a-alerts"
```

#### **En GitHub Actions**
```yaml
- name: Authenticate to Google Cloud
  uses: google-github-actions/auth@v1
  with:
    workload_identity_provider: 'projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider'
    service_account: 'c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com'
```

---

### **Opción 4: gcloud auth login --no-launch-browser**

#### **Para entornos headless**
```bash
# Generar URL de autenticación
gcloud auth login --no-launch-browser

# Copiar la URL y autenticarse en otro dispositivo
# Luego pegar el código de autorización
```

---

## 🛠️ **Configuración Rápida para tu Proyecto**

### **Paso 1: Crear Service Account**
```bash
# Crear proyecto si no existe
gcloud projects create c4a-alerts-platform --name="C4A Alerts Platform"

# Configurar proyecto
gcloud config set project c4a-alerts-platform

# Crear service account
gcloud iam service-accounts create c4a-alerts-sa \
    --display-name="C4A Alerts Service Account"

# Asignar roles
gcloud projects add-iam-policy-binding c4a-alerts-platform \
    --member="serviceAccount:c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com" \
    --role="roles/cloudfunctions.developer"

gcloud projects add-iam-policy-binding c4a-alerts-platform \
    --member="serviceAccount:c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com" \
    --role="roles/datastore.user"

# Crear clave
gcloud iam service-accounts keys create c4a-alerts-key.json \
    --iam-account=c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com
```

### **Paso 2: Configurar GitHub Secrets**
```bash
# Copiar el contenido del archivo JSON
cat c4a-alerts-key.json

# En GitHub: Settings > Secrets > Actions
# Añadir: GCP_SA_KEY = contenido del JSON
```

### **Paso 3: Actualizar Workflow**
```yaml
- name: Authenticate to Google Cloud
  uses: google-github-actions/auth@v1
  with:
    credentials_json: ${{ secrets.GCP_SA_KEY }}

- name: Set up Cloud SDK
  uses: google-github-actions/setup-gcloud@v1
```

---

## 🔒 **Seguridad**

### **Buenas Prácticas**
- ✅ **Usar Service Accounts** para automatización
- ✅ **Principio de menor privilegio** - solo roles necesarios
- ✅ **Rotar claves** regularmente
- ✅ **Usar Workload Identity** en producción
- ❌ **Nunca commitear** claves en el código
- ❌ **No usar credenciales de usuario** para CI/CD

### **Roles Mínimos Necesarios**
```bash
# Para Cloud Functions
roles/cloudfunctions.developer

# Para Firestore
roles/datastore.user

# Para Cloud Build
roles/cloudbuild.builds.builder

# Para Cloud Run (si usas)
roles/run.developer
```

---

## 🚀 **Implementación en tu Proyecto**

### **Actualizar Workflow**
```yaml
name: Deploy Serverless Monitoring Platform

on:
  push:
    branches: [ main ]
  workflow_dispatch:

env:
  PROJECT_ID: c4a-alerts-platform
  FUNCTION_NAME: c4a-alerts-api
  COLLECTION_FUNCTION: c4a-alerts-collector
  REGION: us-central1

jobs:
  deploy-cloud-functions:
    name: Deploy Cloud Functions
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v1

      - name: Deploy Functions
        run: |
          gcloud functions deploy ${{ env.FUNCTION_NAME }} \
            --runtime python310 \
            --trigger-http \
            --allow-unauthenticated \
            --source cloud-function \
            --entry-point process_alert \
            --memory 512MB \
            --timeout 540s \
            --region ${{ env.REGION }}
```

---

## 📋 **Comandos Útiles**

### **Verificar Autenticación**
```bash
# Ver cuenta activa
gcloud auth list

# Ver proyecto configurado
gcloud config get-value project

# Ver credenciales ADC
gcloud auth application-default print-access-token
```

### **Gestionar Service Accounts**
```bash
# Listar service accounts
gcloud iam service-accounts list

# Ver roles de un service account
gcloud projects get-iam-policy c4a-alerts-platform \
    --flatten="bindings[].members" \
    --format="table(bindings.role)" \
    --filter="bindings.members:c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com"
```

### **Eliminar Service Account**
```bash
# Eliminar service account
gcloud iam service-accounts delete c4a-alerts-sa@c4a-alerts-platform.iam.gserviceaccount.com
```

---

## 🎯 **Recomendación Final**

**Para tu proyecto C4A Alerts, usa la Opción 1 (Service Account Key)** porque:

1. ✅ **Más simple** de configurar
2. ✅ **Funciona perfectamente** con GitHub Actions
3. ✅ **Segura** para automatización
4. ✅ **No requiere navegador**
5. ✅ **Fácil de rotar** cuando sea necesario

¿Quieres que te ayude a configurar la Service Account paso a paso?
