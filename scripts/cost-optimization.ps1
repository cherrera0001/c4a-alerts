# C4A Alerts - Cost Optimization Script (PowerShell)
# Monitorea y optimiza el consumo de Google Cloud

param(
    [string]$ProjectId = "c4a-alerts-personal-1756352164",
    [string]$Region = "us-central1"
)

Write-Host "🔍 C4A Alerts - Cost Monitoring & Optimization" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Verificar configuración actual
Write-Host "📊 Current Project: $ProjectId" -ForegroundColor Yellow
Write-Host "📍 Region: $Region" -ForegroundColor Yellow
Write-Host ""

# 1. Verificar uso de Cloud Functions
Write-Host "🔧 Cloud Functions Usage:" -ForegroundColor Green
try {
    $functions = gcloud functions list --project=$ProjectId --region=$Region --format="table(name,status,memory,timeout,url)" 2>$null
    if ($functions) {
        Write-Host $functions
    }
    else {
        Write-Host "No functions found or error accessing functions" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error checking Cloud Functions: $_" -ForegroundColor Red
}

Write-Host ""

# 2. Verificar uso de Firestore
Write-Host "🗄️ Firestore Usage:" -ForegroundColor Green
try {
    $firestore = gcloud firestore databases describe --project=$ProjectId --database='(default)' --format="value(name,locationId,type)" 2>$null
    if ($firestore) {
        Write-Host "Firestore Database: $firestore"
    }
    else {
        Write-Host "Firestore not configured or error accessing database" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error checking Firestore: $_" -ForegroundColor Red
}

Write-Host ""

# 3. Verificar costos estimados (últimos 30 días)
Write-Host "💰 Estimated Costs (Last 30 days):" -ForegroundColor Green
try {
    $billingAccounts = gcloud billing accounts list --format="value(ACCOUNT_ID,NAME,OPEN)" 2>$null
    if ($billingAccounts) {
        foreach ($account in $billingAccounts -split "`n") {
            if ($account -match "True") {
                $parts = $account -split "`t"
                if ($parts.Length -ge 2) {
                    $accountId = $parts[0]
                    $accountName = $parts[1]
                    Write-Host "Billing Account: $accountName ($accountId)" -ForegroundColor Yellow

                    # Intentar obtener presupuestos
                    $budgets = gcloud billing budgets list --billing-account=$accountId --format="value(displayName,amount.specifiedAmount.units,amount.specifiedAmount.currencyCode)" 2>$null
                    if ($budgets) {
                        Write-Host "Budgets: $budgets"
                    }
                    else {
                        Write-Host "No budgets configured" -ForegroundColor Yellow
                    }
                }
            }
        }
    }
    else {
        Write-Host "No billing accounts found" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error checking billing: $_" -ForegroundColor Red
}

Write-Host ""

# 4. Configurar alertas de facturación
Write-Host "🚨 Setting up Billing Alerts..." -ForegroundColor Green
try {
    $billingAccount = gcloud billing accounts list --filter="OPEN=true" --format="value(ACCOUNT_ID)" 2>$null | Select-Object -First 1

    if ($billingAccount) {
        Write-Host "Creating budget alert at 80% of free tier..." -ForegroundColor Yellow

        # Crear presupuesto de $50 USD (dentro del free tier)
        $budgetResult = gcloud billing budgets create --billing-account=$billingAccount --display-name="C4A Alerts Budget" --budget-amount=50USD --threshold-rule=percent=80 --threshold-rule=percent=100 --notification-rule=email=herrera.jara.cristobal@gmail.com 2>$null

        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Budget created successfully" -ForegroundColor Green
        }
        else {
            Write-Host "⚠️ Budget creation failed or already exists" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "No open billing account found" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error setting up billing alerts: $_" -ForegroundColor Red
}

Write-Host ""

# 5. Optimizaciones recomendadas
Write-Host "💡 Cost Optimization Recommendations:" -ForegroundColor Cyan
Write-Host "1. Cloud Functions:" -ForegroundColor White
Write-Host "   - Current: 256MB memory, 300s timeout" -ForegroundColor Gray
Write-Host "   - Free tier: 2M invocations/month" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Firestore:" -ForegroundColor White
Write-Host "   - Free tier: 1GB storage, 50K reads/day" -ForegroundColor Gray
Write-Host "   - Monitor: Use Cloud Monitoring for usage" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Cloud Build:" -ForegroundColor White
Write-Host "   - Free tier: 120 minutes/day" -ForegroundColor Gray
Write-Host "   - Optimize: Use .gcloudignore to reduce build time" -ForegroundColor Gray
Write-Host ""

# 6. Comandos útiles para monitoreo
Write-Host "📈 Useful Monitoring Commands:" -ForegroundColor Cyan
Write-Host "gcloud functions logs read --project=$ProjectId --region=$Region --limit=50" -ForegroundColor Gray
Write-Host "gcloud logging read 'resource.type=cloud_function' --project=$ProjectId --limit=20" -ForegroundColor Gray
Write-Host "gcloud billing accounts list --format='table(ACCOUNT_ID,NAME,OPEN)'" -ForegroundColor Gray
Write-Host ""

Write-Host "✅ Cost monitoring setup complete!" -ForegroundColor Green
Write-Host "💡 Remember: Free tier includes $300 USD for 12 months" -ForegroundColor Yellow

# 7. Verificar estado actual del proyecto
Write-Host ""
Write-Host "🔍 Current Project Status:" -ForegroundColor Cyan
try {
    $projectInfo = gcloud config get-value project 2>$null
    if ($projectInfo -eq $ProjectId) {
        Write-Host "✅ Project is active: $ProjectId" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️ Different project active: $projectInfo" -ForegroundColor Yellow
        Write-Host "   Expected: $ProjectId" -ForegroundColor Gray
    }
}
catch {
    Write-Host "Error checking project status: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎯 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Monitor costs regularly using the commands above" -ForegroundColor White
Write-Host "2. Set up Cloud Monitoring alerts" -ForegroundColor White
Write-Host "3. Review usage patterns monthly" -ForegroundColor White
Write-Host "4. Consider upgrading only if needed" -ForegroundColor White
