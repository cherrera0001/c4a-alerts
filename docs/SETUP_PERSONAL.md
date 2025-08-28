# 🚀 Configuración Personal - C4A Alerts

## 📧 **Tu Ambiente Personal**
- **Usuario**: herrera.jara.cristobal@gmail.com
- **Propósito**: Desarrollo y pruebas personales
- **Sin navegador**: Autenticación por línea de comandos

---

## 🛠️ **Opciones de Configuración**

### **Opción A: WSL Ubuntu (Recomendada)**

Si prefieres usar tu WSL Ubuntu:

```bash
# 1. Abrir WSL Ubuntu
wsl

# 2. Navegar al proyecto
cd /mnt/e/Tools/C4A/c4a-alerts-main/c4a-alerts

# 3. Ejecutar script de configuración
chmod +x scripts/setup-personal-env.sh
./scripts/setup-personal-env.sh
```

### **Opción B: Windows PowerShell**

Si prefieres usar PowerShell:

```powershell
# 1. Abrir PowerShell como Administrador
# 2. Navegar al proyecto
cd E:\Tools\C4A\c4a-alerts-main\c4a-alerts

# 3. Ejecutar script de configuración
.\scripts\setup-personal-env.ps1
```

### **Opción C: Configuración Manual**

Si prefieres hacerlo paso a paso:

```bash
# 1. Instalar Google Cloud SDK
# https://cloud.google.com/sdk/docs/install

# 2. Autenticarse sin navegador
gcloud auth login --no-launch-browser

# 3. Crear proyecto personal
gcloud projects create c4a-alerts-personal-$(date +%s) --name="C4A Alerts Personal"

# 4. Configurar proyecto
gcloud config set project [TU_PROJECT_ID]

# 5. Habilitar APIs
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# 6. Crear Service Account
gcloud iam service-accounts create c4a-alerts-sa --display-name="C4A Alerts Service Account"

# 7. Asignar roles
gcloud projects add-iam-policy-binding [TU_PROJECT_ID] --member="serviceAccount:c4a-alerts-sa@[TU_PROJECT_ID].iam.gserviceaccount.com" --role="roles/cloudfunctions.developer"
gcloud projects add-iam-policy-binding [TU_PROJECT_ID] --member="serviceAccount:c4a-alerts-sa@[TU_PROJECT_ID].iam.gserviceaccount.com" --role="roles/datastore.user"

# 8. Generar clave
gcloud iam service-accounts keys create c4a-alerts-key.json --iam-account=c4a-alerts-sa@[TU_PROJECT_ID].iam.gserviceaccount.com
```

---

## 🔐 **Configurar GitHub Secrets**

Después de la configuración, necesitas configurar estos secrets en GitHub:

1. **Ve a tu repositorio**: https://github.com/cherrera0001/c4a-alerts
2. **Settings > Secrets and variables > Actions**
3. **Añadir estos secrets**:

```
GCP_SA_KEY = [contenido del archivo c4a-alerts-key.json]
GCP_PROJECT_ID = [tu-project-id]
```

---

## 🚀 **Hacer Deploy**

Una vez configurado:

```bash
# 1. Commit y push
git add .
git commit -m "feat: configure personal environment"
git push origin main

# 2. El workflow se ejecutará automáticamente
# 3. Verificar en GitHub Actions
```

---

## 📋 **Verificación**

Para verificar que todo funciona:

```bash
# Verificar autenticación
gcloud auth list

# Verificar proyecto
gcloud config get-value project

# Verificar Service Account
gcloud iam service-accounts list

# Verificar APIs habilitadas
gcloud services list --enabled
```

---

## 🆘 **Solución de Problemas**

### **Error: "gcloud not found"**
```bash
# Instalar Google Cloud SDK
# https://cloud.google.com/sdk/docs/install
```

### **Error: "Permission denied"**
```bash
# Verificar autenticación
gcloud auth login --no-launch-browser
```

### **Error: "Project not found"**
```bash
# Verificar proyecto configurado
gcloud config get-value project
```

---

## 🎯 **Próximos Pasos**

1. ✅ **Elegir opción de configuración**
2. ✅ **Ejecutar script de configuración**
3. ✅ **Configurar GitHub Secrets**
4. ✅ **Hacer deploy automático**
5. ✅ **Probar la plataforma**

**¿Por cuál opción quieres empezar?**
