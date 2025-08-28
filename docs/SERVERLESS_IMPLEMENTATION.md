# Serverless Implementation Guide

## 🎯 **Objetivo**
Transformar C4A Alerts en una plataforma realmente consumible usando Google Cloud Functions + Firestore + Vercel.

## 🚀 **Arquitectura Final**

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

## 📋 **Paso 1: Configurar Google Cloud**

### 1.1 Crear Proyecto
```bash
# Instalar Google Cloud CLI
# https://cloud.google.com/sdk/docs/install

# Autenticarse
gcloud auth login

# Crear proyecto (o usar existente)
gcloud projects create c4a-alerts-platform --name="C4A Alerts Platform"

# Configurar proyecto
gcloud config set project c4a-alerts-platform

# Habilitar APIs necesarias
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### 1.2 Configurar Billing
- Ir a [Google Cloud Console](https://console.cloud.google.com)
- Seleccionar tu proyecto
- Configurar billing (necesario para Cloud Functions)

## 📋 **Paso 2: Crear Cloud Function**

### 2.1 Estructura del Proyecto
```
c4a-alerts/
├── cloud-function/
│   ├── main.py
│   ├── requirements.txt
│   └── .env.yaml
├── frontend/
│   ├── pages/
│   ├── components/
│   └── package.json
└── .github/workflows/
    └── deploy-serverless.yml
```

### 2.2 Cloud Function (main.py)
```python
import functions_framework
import os
import json
from datetime import datetime
from google.cloud import firestore
from c4aalerts.app.workers.jobs import process_alert_pipeline
from c4aalerts.app.schemas.alert import NormalizedAlert

# Inicializar Firestore
db = firestore.Client()

@functions_framework.http
def process_alert(request):
    """HTTP Cloud Function para procesar alertas."""

    # Configurar CORS
    if request.method == 'OPTIONS':
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600'
        }
        return ('', 204, headers)

    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    }

    try:
        # Obtener datos del request
        request_json = request.get_json(silent=True)

        if request.method == 'POST':
            # Procesar nueva alerta
            if request_json and 'alert_data' in request_json:
                result = process_alert_pipeline(request_json['alert_data'])

                # Guardar en Firestore
                alert_ref = db.collection('alerts').document()
                alert_ref.set({
                    'alert_data': request_json['alert_data'],
                    'result': result,
                    'timestamp': datetime.utcnow(),
                    'status': 'processed'
                })

                return (json.dumps(result), 200, headers)

            # Obtener alertas
            elif request_json and 'action' == 'get_alerts':
                alerts = []
                docs = db.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).stream()

                for doc in docs:
                    alerts.append({
                        'id': doc.id,
                        **doc.to_dict()
                    })

                return (json.dumps({'alerts': alerts}), 200, headers)

        elif request.method == 'GET':
            # Health check
            return (json.dumps({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200, headers)

        return (json.dumps({'error': 'Invalid request'}), 400, headers)

    except Exception as e:
        return (json.dumps({'error': str(e)}), 500, headers)

@functions_framework.http
def collect_alerts(request):
    """Cloud Function para recolectar alertas de fuentes."""

    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    }

    try:
        # Tu lógica de recolección aquí
        # Por ahora, simulamos recolección
        collected_alerts = [
            {
                'uid': f'alert_{datetime.utcnow().timestamp()}',
                'source': 'cisa',
                'title': 'Test Alert',
                'severity': 'high',
                'content_hash': 'test123456789'
            }
        ]

        # Procesar cada alerta
        results = []
        for alert_data in collected_alerts:
            result = process_alert_pipeline(alert_data)

            # Guardar en Firestore
            alert_ref = db.collection('alerts').document()
            alert_ref.set({
                'alert_data': alert_data,
                'result': result,
                'timestamp': datetime.utcnow(),
                'status': 'collected'
            })

            results.append(result)

        return (json.dumps({
            'status': 'success',
            'alerts_collected': len(collected_alerts),
            'results': results
        }), 200, headers)

    except Exception as e:
        return (json.dumps({'error': str(e)}), 500, headers)
```

### 2.3 Requirements para Cloud Function
```txt
functions-framework==3.*
google-cloud-firestore==2.*
c4aalerts==2.0.0
fastapi==0.104.1
pydantic==2.5.0
celery==5.3.4
redis==5.0.1
```

## 📋 **Paso 3: Frontend en Vercel**

### 3.1 Crear Proyecto Next.js
```bash
# Crear directorio frontend
mkdir frontend
cd frontend

# Inicializar Next.js
npx create-next-app@latest . --typescript --tailwind --eslint
```

### 3.2 Página Principal (pages/index.tsx)
```tsx
import { useState, useEffect } from 'react'
import Head from 'next/head'

interface Alert {
  id: string
  alert_data: any
  result: any
  timestamp: string
  status: string
}

export default function Home() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAlerts()
  }, [])

  const fetchAlerts = async () => {
    try {
      const response = await fetch('/api/alerts')
      const data = await response.json()
      setAlerts(data.alerts || [])
    } catch (error) {
      console.error('Error fetching alerts:', error)
    } finally {
      setLoading(false)
    }
  }

  const triggerCollection = async () => {
    try {
      const response = await fetch('/api/collect', {
        method: 'POST'
      })
      const data = await response.json()
      alert(`Collection triggered: ${data.alerts_collected} alerts collected`)
      fetchAlerts() // Refresh alerts
    } catch (error) {
      console.error('Error triggering collection:', error)
    }
  }

  return (
    <>
      <Head>
        <title>C4A Alerts Platform</title>
        <meta name="description" content="Threat Intelligence & Alerting Platform" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <main className="min-h-screen bg-gray-50">
        <div className="container mx-auto px-4 py-8">
          <div className="flex justify-between items-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900">
              C4A Alerts Platform
            </h1>
            <button
              onClick={triggerCollection}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
            >
              Trigger Collection
            </button>
          </div>

          {loading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
              <p className="mt-4 text-gray-600">Loading alerts...</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {alerts.map((alert) => (
                <div key={alert.id} className="bg-white p-6 rounded-lg shadow">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">
                        {alert.alert_data?.title || 'Untitled Alert'}
                      </h3>
                      <p className="text-gray-600 mt-1">
                        Source: {alert.alert_data?.source || 'Unknown'}
                      </p>
                      <p className="text-gray-600">
                        Severity: {alert.alert_data?.severity || 'Unknown'}
                      </p>
                    </div>
                    <span className={`px-2 py-1 rounded text-sm font-medium ${
                      alert.status === 'processed' ? 'bg-green-100 text-green-800' :
                      alert.status === 'collected' ? 'bg-blue-100 text-blue-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {alert.status}
                    </span>
                  </div>
                  <p className="text-gray-500 text-sm mt-2">
                    {new Date(alert.timestamp).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </>
  )
}
```

### 3.3 API Routes (pages/api/alerts.ts)
```typescript
import type { NextApiRequest, NextApiResponse } from 'next'

const CLOUD_FUNCTION_URL = process.env.CLOUD_FUNCTION_URL

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method === 'GET') {
    try {
      const response = await fetch(`${CLOUD_FUNCTION_URL}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'get_alerts'
        })
      })

      const data = await response.json()
      res.status(200).json(data)
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch alerts' })
    }
  } else {
    res.setHeader('Allow', ['GET'])
    res.status(405).end(`Method ${req.method} Not Allowed`)
  }
}
```

## 📋 **Paso 4: GitHub Actions para Deploy**

### 4.1 Workflow de Deploy (.github/workflows/deploy-serverless.yml)
```yaml
name: Deploy Serverless Platform

on:
  push:
    branches: [ main ]
  workflow_dispatch:

env:
  PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
  FUNCTION_NAME: c4a-alerts-api
  REGION: us-central1

jobs:
  deploy-cloud-function:
    name: Deploy Cloud Function
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install -r cloud-function/requirements.txt

      - name: Deploy to Cloud Function
        run: |
          gcloud functions deploy ${{ env.FUNCTION_NAME }} \
            --runtime python310 \
            --trigger-http \
            --allow-unauthenticated \
            --source cloud-function \
            --entry-point process_alert \
            --memory 512MB \
            --timeout 540s \
            --region ${{ env.REGION }} \
            --project ${{ env.PROJECT_ID }}

      - name: Get Function URL
        id: function-url
        run: |
          URL=$(gcloud functions describe ${{ env.FUNCTION_NAME }} \
            --region=${{ env.REGION }} \
            --project=${{ env.PROJECT_ID }} \
            --format="value(httpsTrigger.url)")
          echo "url=$URL" >> $GITHUB_OUTPUT

      - name: Update Environment Variables
        run: |
          echo "CLOUD_FUNCTION_URL=${{ steps.function-url.outputs.url }}" >> $GITHUB_ENV

  deploy-frontend:
    name: Deploy Frontend
    runs-on: ubuntu-latest
    needs: deploy-cloud-function
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Install dependencies
        run: |
          cd frontend
          npm install

      - name: Build application
        run: |
          cd frontend
          npm run build
        env:
          CLOUD_FUNCTION_URL: ${{ needs.deploy-cloud-function.outputs.function-url }}

      - name: Deploy to Vercel
        uses: amondnet/vercel-action@v25
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.VERCEL_ORG_ID }}
          vercel-project-id: ${{ secrets.VERCEL_PROJECT_ID }}
          working-directory: ./frontend
```

## 📋 **Paso 5: Configurar Secrets**

### 5.1 GitHub Secrets Necesarios
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

## 🚀 **Próximos Pasos**

1. **Configurar Google Cloud** y crear proyecto
2. **Implementar Cloud Function** con el código proporcionado
3. **Crear frontend** en Vercel
4. **Configurar GitHub Actions** para deploy automático
5. **Probar la plataforma** completa

¿Quieres que empecemos con la implementación paso a paso?
