# C4A Alerts - Personal Environment Setup (PowerShell)
# Para: herrera.jara.cristobal@gmail.com

param(
    [switch]$SkipGCloudInstall
)

# Colores para output
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

Write-Host "🚀 Configurando ambiente personal para C4A Alerts..." -ForegroundColor $Green
Write-Host "📧 Usuario: herrera.jara.cristobal@gmail.com" -ForegroundColor $Green
Write-Host ""

# 1. Verificar si gcloud está instalado
Write-Status "Verificando Google Cloud SDK..."
try {
    $gcloudVersion = gcloud version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Google Cloud SDK ya está instalado"
    }
    else {
        throw "gcloud no encontrado"
    }
}
catch {
    Write-Warning "Google Cloud SDK no está instalado"

    if (-not $SkipGCloudInstall) {
        Write-Status "Instalando Google Cloud SDK..."
        Write-Warning "Por favor instala Google Cloud SDK manualmente desde:"
        Write-Host "https://cloud.google.com/sdk/docs/install" -ForegroundColor $Yellow
        Write-Host ""
        Write-Host "O ejecuta este script con -SkipGCloudInstall para continuar sin instalarlo"
        exit 1
    }
    else {
        Write-Warning "Continuando sin Google Cloud SDK..."
    }
}

# 2. Autenticación sin navegador
Write-Status "Configurando autenticación sin navegador..."
Write-Warning "Se abrirá una URL para autenticarte. Copia la URL y ábrela en tu navegador"
Write-Warning "Luego pega el código de autorización aquí"

try {
    gcloud auth login --no-launch-browser
    Write-Success "Autenticación completada"
}
catch {
    Write-Error "Error en la autenticación: $_"
    exit 1
}

# 3. Crear proyecto personal
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$PROJECT_ID = "c4a-alerts-personal-$timestamp"
Write-Status "Creando proyecto personal: $PROJECT_ID"

try {
    gcloud projects create $PROJECT_ID --name="C4A Alerts Personal" --set-as-default
    Write-Success "Proyecto creado exitosamente"
}
catch {
    Write-Error "Error creando proyecto: $_"
    exit 1
}

# 4. Habilitar APIs necesarias
Write-Status "Habilitando APIs necesarias..."
$apis = @(
    "cloudfunctions.googleapis.com",
    "firestore.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com"
)

foreach ($api in $apis) {
    try {
        gcloud services enable $api
        Write-Success "API $api habilitada"
    }
    catch {
        Write-Warning "Error habilitando API $api: $_"
    }
}

# 5. Configurar Firestore
Write-Status "Configurando Firestore..."
try {
    gcloud firestore databases create --region=us-central1
    Write-Success "Firestore configurado"
}
catch {
    Write-Warning "Error configurando Firestore: $_"
}

# 6. Crear Service Account para automatización
Write-Status "Creando Service Account para automatización..."
try {
    gcloud iam service-accounts create c4a-alerts-sa `
        --display-name="C4A Alerts Service Account" `
        --description="Service account for personal C4A Alerts platform"
    Write-Success "Service Account creada"
}
catch {
    Write-Error "Error creando Service Account: $_"
    exit 1
}

# 7. Asignar roles necesarios
Write-Status "Asignando roles a la Service Account..."
$roles = @(
    "roles/cloudfunctions.developer",
    "roles/datastore.user",
    "roles/cloudbuild.builds.builder"
)

foreach ($role in $roles) {
    try {
        gcloud projects add-iam-policy-binding $PROJECT_ID `
            --member="serviceAccount:c4a-alerts-sa@${PROJECT_ID}.iam.gserviceaccount.com" `
            --role=$role
        Write-Success "Rol $role asignado"
    }
    catch {
        Write-Warning "Error asignando rol $role: $_"
    }
}

# 8. Crear clave de Service Account
Write-Status "Generando clave de Service Account..."
try {
    gcloud iam service-accounts keys create c4a-alerts-key.json `
        --iam-account="c4a-alerts-sa@${PROJECT_ID}.iam.gserviceaccount.com"
    Write-Success "Clave de Service Account generada"
}
catch {
    Write-Error "Error generando clave: $_"
    exit 1
}

# 9. Configurar variables de entorno
Write-Status "Configurando variables de entorno..."
$envContent = @"
# C4A Alerts - Personal Environment
GCP_PROJECT_ID=$PROJECT_ID
GCP_REGION=us-central1
ENVIRONMENT=personal
"@

$envContent | Out-File -FilePath ".env.personal" -Encoding UTF8
Write-Success "Archivo .env.personal creado"

# 10. Mostrar información de configuración
Write-Success "¡Configuración completada!"
Write-Host ""
Write-Host "📋 Información de configuración:" -ForegroundColor $Green
Write-Host "   Proyecto ID: $PROJECT_ID" -ForegroundColor $Blue
Write-Host "   Región: us-central1" -ForegroundColor $Blue
Write-Host "   Service Account: c4a-alerts-sa@$PROJECT_ID.iam.gserviceaccount.com" -ForegroundColor $Blue
Write-Host "   Archivo de clave: c4a-alerts-key.json" -ForegroundColor $Blue
Write-Host ""

# 11. Mostrar contenido de la clave para GitHub Secrets
Write-Status "Contenido de la clave para GitHub Secrets (GCP_SA_KEY):"
Write-Host ""
try {
    Get-Content "c4a-alerts-key.json" | Write-Host
}
catch {
    Write-Error "No se pudo leer el archivo de clave"
}
Write-Host ""

Write-Warning "IMPORTANTE: Copia el contenido JSON de arriba y configúralo en GitHub Secrets como GCP_SA_KEY"
Write-Warning "También configura GCP_PROJECT_ID=$PROJECT_ID en GitHub Secrets"

# 12. Verificar configuración
Write-Status "Verificando configuración..."
try {
    gcloud config list
}
catch {
    Write-Warning "No se pudo verificar la configuración"
}
Write-Host ""

Write-Success "¡Tu ambiente personal está listo para usar!"
Write-Status "Próximo paso: Configurar GitHub Secrets y hacer deploy"
