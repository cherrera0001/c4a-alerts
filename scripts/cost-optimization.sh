#!/bin/bash

# C4A Alerts - Cost Optimization Script
# Monitorea y optimiza el consumo de Google Cloud

set -e

PROJECT_ID="c4a-alerts-personal-1756352164"
REGION="us-central1"

echo "🔍 C4A Alerts - Cost Monitoring & Optimization"
echo "================================================"

# Verificar configuración actual
echo "📊 Current Project: $PROJECT_ID"
echo "📍 Region: $REGION"
echo ""

# 1. Verificar uso de Cloud Functions
echo "🔧 Cloud Functions Usage:"
gcloud functions list --project=$PROJECT_ID --region=$REGION --format="table(name,status,memory,timeout,url)"

echo ""

# 2. Verificar uso de Firestore
echo "🗄️ Firestore Usage:"
gcloud firestore databases describe --project=$PROJECT_ID --database="(default)" --format="value(name,locationId,type)"

echo ""

# 3. Verificar costos estimados (últimos 30 días)
echo "💰 Estimated Costs (Last 30 days):"
gcloud billing accounts list --format="value(ACCOUNT_ID,NAME,OPEN)" | while read account_id name open; do
    if [ "$open" = "True" ]; then
        echo "Billing Account: $name ($account_id)"
        gcloud billing budgets list --billing-account=$account_id --format="value(displayName,amount.specifiedAmount.units,amount.specifiedAmount.currencyCode)" 2>/dev/null || echo "No budgets configured"
    fi
done

echo ""

# 4. Configurar alertas de facturación
echo "🚨 Setting up Billing Alerts..."
BILLING_ACCOUNT=$(gcloud billing accounts list --filter="OPEN=true" --format="value(ACCOUNT_ID)" | head -1)

if [ -n "$BILLING_ACCOUNT" ]; then
    echo "Creating budget alert at 80% of free tier..."

    # Crear presupuesto de $50 USD (dentro del free tier)
    gcloud billing budgets create \
        --billing-account=$BILLING_ACCOUNT \
        --display-name="C4A Alerts Budget" \
        --budget-amount=50USD \
        --threshold-rule=percent=80 \
        --threshold-rule=percent=100 \
        --notification-rule=pubsub-topic=projects/$PROJECT_ID/topics/billing-alerts \
        --notification-rule=email=herrera.jara.cristobal@gmail.com || echo "Budget creation failed or already exists"
fi

echo ""

# 5. Optimizaciones recomendadas
echo "💡 Cost Optimization Recommendations:"
echo "1. Cloud Functions:"
echo "   - Current: 512MB memory, 540s timeout"
echo "   - Optimize: Reduce to 256MB, 300s timeout"
echo "   - Free tier: 2M invocations/month"
echo ""
echo "2. Firestore:"
echo "   - Free tier: 1GB storage, 50K reads/day"
echo "   - Monitor: Use Cloud Monitoring for usage"
echo ""
echo "3. Cloud Build:"
echo "   - Free tier: 120 minutes/day"
echo "   - Optimize: Use .gcloudignore to reduce build time"
echo ""

# 6. Comandos útiles para monitoreo
echo "📈 Useful Monitoring Commands:"
echo "gcloud functions logs read --project=$PROJECT_ID --region=$REGION --limit=50"
echo "gcloud logging read 'resource.type=cloud_function' --project=$PROJECT_ID --limit=20"
echo "gcloud billing accounts list --format='table(ACCOUNT_ID,NAME,OPEN)'"
echo ""

echo "✅ Cost monitoring setup complete!"
echo "💡 Remember: Free tier includes $300 USD for 12 months"
