#!/bin/bash

# C4A Alerts - Personal Environment Setup
# Para: herrera.jara.cristobal@gmail.com

set -e

echo "🚀 Configurando ambiente personal para C4A Alerts..."
echo "📧 Usuario: herrera.jara.cristobal@gmail.com"
echo ""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir con colores
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 1. Verificar si gcloud está instalado
print_status "Verificando Google Cloud SDK..."
if ! command -v gcloud &> /dev/null; then
    print_warning "Google Cloud SDK no está instalado"
    print_status "Instalando Google Cloud SDK..."

    # Instalar Google Cloud SDK
    curl https://sdk.cloud.google.com | bash
    exec -l $SHELL

    # Verificar instalación
    if ! command -v gcloud &> /dev/null; then
        print_error "No se pudo instalar Google Cloud SDK"
        exit 1
    fi
else
    print_success "Google Cloud SDK ya está instalado"
fi

# 2. Autenticación sin navegador
print_status "Configurando autenticación sin navegador..."
print_warning "Se abrirá una URL para autenticarte. Copia la URL y ábrela en tu navegador"
print_warning "Luego pega el código de autorización aquí"

gcloud auth login --no-launch-browser

# 3. Crear proyecto personal
PROJECT_ID="c4a-alerts-personal-$(date +%s)"
print_status "Creando proyecto personal: $PROJECT_ID"

gcloud projects create $PROJECT_ID --name="C4A Alerts Personal" --set-as-default

# 4. Habilitar APIs necesarias
print_status "Habilitando APIs necesarias..."
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com

# 5. Configurar Firestore
print_status "Configurando Firestore..."
gcloud firestore databases create --region=us-central1

# 6. Crear Service Account para automatización
print_status "Creando Service Account para automatización..."
gcloud iam service-accounts create c4a-alerts-sa \
    --display-name="C4A Alerts Service Account" \
    --description="Service account for personal C4A Alerts platform"

# 7. Asignar roles necesarios
print_status "Asignando roles a la Service Account..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:c4a-alerts-sa@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudfunctions.developer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:c4a-alerts-sa@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/datastore.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:c4a-alerts-sa@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudbuild.builds.builder"

# 8. Crear clave de Service Account
print_status "Generando clave de Service Account..."
gcloud iam service-accounts keys create c4a-alerts-key.json \
    --iam-account=c4a-alerts-sa@$PROJECT_ID.iam.gserviceaccount.com

# 9. Configurar variables de entorno
print_status "Configurando variables de entorno..."
cat > .env.personal << EOF
# C4A Alerts - Personal Environment
GCP_PROJECT_ID=$PROJECT_ID
GCP_REGION=us-central1
ENVIRONMENT=personal
EOF

# 10. Mostrar información de configuración
print_success "¡Configuración completada!"
echo ""
echo "📋 Información de configuración:"
echo "   Proyecto ID: $PROJECT_ID"
echo "   Región: us-central1"
echo "   Service Account: c4a-alerts-sa@$PROJECT_ID.iam.gserviceaccount.com"
echo "   Archivo de clave: c4a-alerts-key.json"
echo ""

# 11. Mostrar contenido de la clave para GitHub Secrets
print_status "Contenido de la clave para GitHub Secrets (GCP_SA_KEY):"
echo ""
cat c4a-alerts-key.json
echo ""

print_warning "IMPORTANTE: Copia el contenido JSON de arriba y configúralo en GitHub Secrets como GCP_SA_KEY"
print_warning "También configura GCP_PROJECT_ID=$PROJECT_ID en GitHub Secrets"

# 12. Verificar configuración
print_status "Verificando configuración..."
gcloud config list
echo ""

print_success "¡Tu ambiente personal está listo para usar!"
print_status "Próximo paso: Configurar GitHub Secrets y hacer deploy"
