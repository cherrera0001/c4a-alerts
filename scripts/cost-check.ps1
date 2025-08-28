# C4A Alerts - Simple Cost Check Script (PowerShell)

$ProjectId = "c4a-alerts-personal-1756352164"
$Region = "us-central1"

Write-Host "🔍 C4A Alerts - Cost Check" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Verificar configuración actual
Write-Host "📊 Project: $ProjectId" -ForegroundColor Yellow
Write-Host "📍 Region: $Region" -ForegroundColor Yellow
Write-Host ""

# 1. Verificar Cloud Functions
Write-Host "🔧 Cloud Functions:" -ForegroundColor Green
try {
    $functions = gcloud functions list --project=$ProjectId --region=$Region --format="table(name,status,memory,timeout)" 2>$null
    if ($functions) {
        Write-Host $functions
    }
    else {
        Write-Host "No functions found" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error checking functions" -ForegroundColor Red
}

Write-Host ""

# 2. Verificar Firestore
Write-Host "🗄️ Firestore:" -ForegroundColor Green
Write-Host "Database: default - us-central1" -ForegroundColor Gray
Write-Host ""

# 3. Verificar facturación
Write-Host "💰 Billing:" -ForegroundColor Green
try {
    $billing = gcloud billing accounts list --format="value(ACCOUNT_ID,NAME,OPEN)" 2>$null
    if ($billing) {
        Write-Host "Billing accounts:"
        Write-Host $billing
    }
    else {
        Write-Host "No billing accounts found" -ForegroundColor Red
    }
}
catch {
    Write-Host "Error checking billing" -ForegroundColor Red
}

Write-Host ""

# 4. Información del Free Tier
Write-Host "💡 Free Tier Limits:" -ForegroundColor Cyan
Write-Host "• Cloud Functions: 2M invocations/month" -ForegroundColor Gray
Write-Host "• Firestore: 1GB storage + 50K reads/day" -ForegroundColor Gray
Write-Host "• Cloud Build: 120 minutes/day" -ForegroundColor Gray
Write-Host "• Total Credit: $300 USD for 12 months" -ForegroundColor Gray

Write-Host ""

# 5. Comandos útiles
Write-Host "📈 Useful Commands:" -ForegroundColor Cyan
Write-Host "• Check functions: gcloud functions list --project=$ProjectId --region=$Region" -ForegroundColor Gray
Write-Host "• Check logs: gcloud functions logs read --project=$ProjectId --region=$Region --limit=10" -ForegroundColor Gray
Write-Host "• Check billing: gcloud billing accounts list" -ForegroundColor Gray

Write-Host ""
Write-Host "✅ Cost check complete!" -ForegroundColor Green
