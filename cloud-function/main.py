import functions_framework
import os
import json
from datetime import datetime, timedelta
from google.cloud import firestore
from typing import Dict, List, Any, Optional
import hashlib
import logging

# Importar collectors
try:
    from collectors.misp_csirt import misp_csirt_collector
except ImportError:
    misp_csirt_collector = None
    logging.warning("MISP CSIRT collector no disponible")

# Importar notificadores
try:
    from notifiers.telegram_notifier import telegram_notifier
except ImportError:
    telegram_notifier = None
    logging.warning("Telegram notifier no disponible")

# Inicializar Firestore
db = firestore.Client()

def generate_content_hash(content: str) -> str:
    """Generate a hash for content deduplication."""
    # ⚠️ SEGURIDAD: Usar SHA-256 en lugar de MD5
    return hashlib.sha256(content.encode()).hexdigest()

@functions_framework.http
def process_alert(request):
    """HTTP Cloud Function para procesar alertas y monitoreo."""

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
        request_json = request.get_json(silent=True)

        if request.method == 'POST':
            # Procesar nueva alerta
            if request_json and 'alert_data' in request_json:
                alert_data = request_json['alert_data']

                # Generar hash para deduplicación
                content_hash = generate_content_hash(
                    f"{alert_data.get('title', '')}{alert_data.get('description', '')}{alert_data.get('source', '')}"
                )

                # Verificar si ya existe
                existing = db.collection('alerts').where('content_hash', '==', content_hash).limit(1).stream()
                if list(existing):
                    return (json.dumps({
                        'status': 'duplicate',
                        'message': 'Alert already exists'
                    }), 200, headers)

                # Procesar y enriquecer alerta
                enriched_alert = enrich_alert_data(alert_data, content_hash)

                # Guardar en Firestore
                alert_ref = db.collection('alerts').document()
                alert_ref.set({
                    'alert_data': enriched_alert,
                    'content_hash': content_hash,
                    'timestamp': datetime.utcnow(),
                    'status': 'processed',
                    'priority_score': calculate_priority(enriched_alert),
                    'tags': enriched_alert.get('tags', []),
                    'severity': enriched_alert.get('severity', 'medium'),
                    'source': enriched_alert.get('source', 'unknown')
                })

                # Actualizar estadísticas
                update_statistics(enriched_alert)

                # Enviar notificaciones
                notification_results = send_notifications(enriched_alert)

                return (json.dumps({
                    'status': 'success',
                    'alert_id': alert_ref.id,
                    'priority_score': calculate_priority(enriched_alert),
                    'notifications': notification_results
                }), 200, headers)

            # Obtener alertas con filtros
            elif request_json and request_json.get('action') == 'get_alerts':
                filters = request_json.get('filters', {})
                limit = request_json.get('limit', 50)
                offset = request_json.get('offset', 0)

                alerts = get_filtered_alerts(filters, limit, offset)
                return (json.dumps({'alerts': alerts}), 200, headers)

            # Obtener dashboard data
            elif request_json and request_json.get('action') == 'get_dashboard':
                dashboard_data = get_dashboard_data()
                return (json.dumps(dashboard_data), 200, headers)

            # Obtener estadísticas
            elif request_json and request_json.get('action') == 'get_statistics':
                stats = get_statistics()
                return (json.dumps(stats), 200, headers)

        elif request.method == 'GET':
            # Manejar rutas del dashboard
            path = request.path.strip('/')

            if path == '' or path == 'dashboard':
                return serve_dashboard(request)
            elif path == 'health':
                return get_health(request)
            elif path == 'stats':
                return get_stats(request)
            elif path == 'alerts':
                return get_alerts(request)
            else:
                # Intentar servir el dashboard por defecto
                return serve_dashboard(request)

        return (json.dumps({'error': 'Invalid request'}), 400, headers)

    except Exception as e:
        return (json.dumps({'error': str(e)}), 500, headers)

@functions_framework.http
def collect_alerts(request):
    """Cloud Function para recolectar alertas de fuentes de amenazas."""

    headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    }

    try:
        collected_alerts = []

        # 1. Recolectar desde MISP CSIRT (fuente real)
        if misp_csirt_collector:
            try:
                misp_alerts = misp_csirt_collector.collect_all(days_back=7)
                collected_alerts.extend(misp_alerts)
                logging.info(f"Recolectadas {len(misp_alerts)} alertas desde MISP CSIRT")
            except Exception as e:
                logging.error(f"Error recolectando desde MISP CSIRT: {e}")

        # 2. Simular otras fuentes (para testing)
        if not collected_alerts:  # Solo si no hay alertas reales
            sources = ['cisa', 'nvd', 'mitre', 'virustotal', 'abuseipdb']

            for source in sources:
                # Simular alertas de cada fuente
                alert_data = {
                    'uid': f'alert_{datetime.utcnow().timestamp()}_{source}',
                    'source': source,
                    'title': f'New {source.upper()} Threat Detected',
                    'description': f'Critical vulnerability detected in {source} database',
                    'severity': 'high' if source in ['cisa', 'nvd'] else 'medium',
                    'tags': ['vulnerability', source, 'critical'],
                    'cve_id': f'CVE-2024-{source.upper()}-001',
                    'cvss_score': 8.5 if source in ['cisa', 'nvd'] else 6.0,
                    'epss_score': 0.75 if source in ['cisa', 'nvd'] else 0.45,
                    'confidence': 0.9 if source in ['cisa', 'nvd'] else 0.7,
                    'references': [f'https://{source}.gov/alert/001'],
                    'published_at': datetime.utcnow().isoformat()
                }
                collected_alerts.append(alert_data)

        # Procesar cada alerta
        results = []
        for alert_data in collected_alerts:
            # Verificar duplicados
            content_hash = generate_content_hash(
                f"{alert_data.get('title', '')}{alert_data.get('description', '')}{alert_data.get('source', '')}"
            )

            existing = db.collection('alerts').where('content_hash', '==', content_hash).limit(1).stream()
            if not list(existing):
                # Enriquecer y guardar
                enriched_alert = enrich_alert_data(alert_data, content_hash)
                alert_ref = db.collection('alerts').document()
                alert_ref.set({
                    'alert_data': enriched_alert,
                    'content_hash': content_hash,
                    'timestamp': datetime.utcnow(),
                    'status': 'collected',
                    'priority_score': calculate_priority(enriched_alert),
                    'tags': enriched_alert.get('tags', []),
                    'severity': enriched_alert.get('severity', 'medium'),
                    'source': enriched_alert.get('source', 'unknown')
                })

                results.append({
                    'alert_id': alert_ref.id,
                    'status': 'collected',
                    'priority_score': calculate_priority(enriched_alert)
                })
            else:
                results.append({
                    'alert_id': None,
                    'status': 'duplicate',
                    'priority_score': 0
                })

        return (json.dumps({
            'status': 'success',
            'alerts_collected': len(collected_alerts),
            'alerts_processed': len([r for r in results if r['status'] == 'collected']),
            'alerts_duplicates': len([r for r in results if r['status'] == 'duplicate']),
            'results': results
        }), 200, headers)

    except Exception as e:
        return (json.dumps({'error': str(e)}), 500, headers)

def enrich_alert_data(alert_data: Dict[str, Any], content_hash: str) -> Dict[str, Any]:
    """Enriquecer datos de alerta con información adicional."""
    enriched = alert_data.copy()

    # Asegurar campos requeridos
    enriched.setdefault('uid', f"alert_{datetime.utcnow().timestamp()}")
    enriched.setdefault('source', 'unknown')
    enriched.setdefault('title', 'Untitled Alert')
    enriched.setdefault('description', '')
    enriched.setdefault('severity', 'medium')
    enriched.setdefault('tags', [])
    enriched.setdefault('confidence', 0.5)
    enriched.setdefault('content_hash', content_hash)

    # Añadir tags automáticos basados en severidad
    if enriched['severity'] in ['high', 'critical']:
        enriched['tags'].extend(['urgent', 'high-priority'])

    # Añadir tags basados en fuente
    if enriched['source'] in ['cisa', 'nvd']:
        enriched['tags'].extend(['official', 'verified'])

    return enriched

def calculate_priority(alert_data: Dict[str, Any]) -> float:
    """Calcular puntuación de prioridad basada en múltiples factores."""
    score = 0.0

    # Severidad (0-10)
    severity_scores = {
        'low': 2.5,
        'medium': 5.0,
        'high': 7.5,
        'critical': 10.0
    }
    score += severity_scores.get(alert_data.get('severity', 'medium'), 5.0) * 0.4

    # CVSS Score (0-10)
    cvss_score = alert_data.get('cvss_score', 0)
    score += cvss_score * 0.3

    # EPSS Score (0-1, convert to 0-10)
    epss_score = alert_data.get('epss_score', 0)
    score += epss_score * 10.0 * 0.2

    # Confidence (0-1, convert to 0-10)
    confidence = alert_data.get('confidence', 0.5)
    score += confidence * 10.0 * 0.1

    return min(score, 10.0)

def get_filtered_alerts(filters: Dict[str, Any], limit: int, offset: int) -> List[Dict[str, Any]]:
    """Obtener alertas con filtros aplicados."""
    query = db.collection('alerts')

    # Aplicar filtros
    if filters.get('severity'):
        query = query.where('severity', '==', filters['severity'])

    if filters.get('source'):
        query = query.where('source', '==', filters['source'])

    if filters.get('status'):
        query = query.where('status', '==', filters['status'])

    if filters.get('tags'):
        # Buscar alertas que contengan al menos uno de los tags
        tag = filters['tags'][0]  # Simplificado para Firestore
        query = query.where('tags', 'array_contains', tag)

    # Ordenar por timestamp descendente
    query = query.order_by('timestamp', direction=firestore.Query.DESCENDING)

    # Aplicar paginación
    query = query.offset(offset).limit(limit)

    alerts = []
    for doc in query.stream():
        alert_data = doc.to_dict()
        alert_data['id'] = doc.id
        alerts.append(alert_data)

    return alerts

def get_dashboard_data() -> Dict[str, Any]:
    """Obtener datos para el dashboard."""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    # Estadísticas de las últimas 24 horas
    recent_alerts = db.collection('alerts').where('timestamp', '>=', last_24h).stream()
    recent_count = len(list(recent_alerts))

    # Alertas por severidad
    critical_alerts = db.collection('alerts').where('severity', '==', 'critical').where('timestamp', '>=', last_24h).stream()
    high_alerts = db.collection('alerts').where('severity', '==', 'high').where('timestamp', '>=', last_24h).stream()

    # Fuentes más activas
    sources_query = db.collection('alerts').where('timestamp', '>=', last_7d).stream()
    source_counts = {}
    for doc in sources_query:
        source = doc.to_dict().get('source', 'unknown')
        source_counts[source] = source_counts.get(source, 0) + 1

    return {
        'recent_alerts': recent_count,
        'critical_alerts': len(list(critical_alerts)),
        'high_alerts': len(list(high_alerts)),
        'top_sources': sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        'last_updated': now.isoformat()
    }

def get_statistics() -> Dict[str, Any]:
    """Obtener estadísticas generales."""
    now = datetime.utcnow()
    last_30d = now - timedelta(days=30)

    # Total de alertas
    total_alerts = db.collection('alerts').stream()
    total_count = len(list(total_alerts))

    # Alertas del último mes
    monthly_alerts = db.collection('alerts').where('timestamp', '>=', last_30d).stream()
    monthly_count = len(list(monthly_alerts))

    # Distribución por severidad
    severity_counts = {}
    for severity in ['low', 'medium', 'high', 'critical']:
        severity_query = db.collection('alerts').where('severity', '==', severity).stream()
        severity_counts[severity] = len(list(severity_query))

    return {
        'total_alerts': total_count,
        'monthly_alerts': monthly_count,
        'severity_distribution': severity_counts,
        'last_updated': now.isoformat()
    }

def update_statistics(alert_data: Dict[str, Any]):
    """Actualizar estadísticas en tiempo real."""
    # Esta función puede actualizar contadores en tiempo real
    # Por ahora es un placeholder para futuras optimizaciones
    pass

def send_notifications(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Enviar notificaciones a todos los canales configurados"""
    results = {}

    # Telegram
    if telegram_notifier and telegram_notifier.is_configured():
        try:
            success = telegram_notifier.send_alert(alert_data)
            results['telegram'] = {
                'status': 'success' if success else 'failed',
                'configured': True
            }
        except Exception as e:
            logging.error(f"Error enviando notificación a Telegram: {e}")
            results['telegram'] = {
                'status': 'error',
                'configured': True,
                'error': str(e)
            }
    else:
        results['telegram'] = {
            'status': 'not_configured',
            'configured': False
        }

    return results

def serve_dashboard(request):
    """Sirve el dashboard HTML"""
    try:
        # Leer el archivo HTML
        html_path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()

        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'text/html; charset=utf-8'
        }
        return (html_content, 200, headers)
    except Exception as e:
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
        }
        return (json.dumps({'error': 'Dashboard not available'}), 500, headers)

def get_health(request):
    """Endpoint de health check"""
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    }

    if request.method == 'OPTIONS':
        return ('', 204, headers)

    try:
        # Verificar conexión a Firestore
        db.collection('alerts').limit(1).stream()

        return (json.dumps({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'c4a-alerts-api'
        }), 200, headers)
    except Exception as e:
        return (json.dumps({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500, headers)

def get_stats(request):
    """Obtiene estadísticas del sistema"""
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    }

    if request.method == 'OPTIONS':
        return ('', 204, headers)

    try:
        # Obtener estadísticas de Firestore
        alerts_ref = db.collection('alerts')

        # Total de alertas
        total_alerts = len(list(alerts_ref.stream()))

        # Alertas de hoy
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_alerts = len(list(alerts_ref.where('timestamp', '>=', today).stream()))

        # Alertas críticas
        critical_alerts = len(list(alerts_ref.where('severity', '==', 'critical').stream()))

        # IOCs únicos (simplificado)
        unique_iocs = 0
        for alert in alerts_ref.stream():
            alert_data = alert.to_dict()
            if 'alert_data' in alert_data and 'iocs' in alert_data['alert_data']:
                unique_iocs += len(alert_data['alert_data']['iocs'])

        stats = {
            'total_alerts': total_alerts,
            'today_alerts': today_alerts,
            'critical_alerts': critical_alerts,
            'unique_iocs': unique_iocs,
            'timestamp': datetime.utcnow().isoformat()
        }

        return (json.dumps(stats), 200, headers)
    except Exception as e:
        return (json.dumps({'error': str(e)}), 500, headers)

def get_alerts(request):
    """Obtiene alertas recientes"""
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    }

    if request.method == 'OPTIONS':
        return ('', 204, headers)

    try:
        # Obtener parámetros
        limit = int(request.args.get('limit', 10))

        # Obtener alertas recientes
        alerts_ref = db.collection('alerts').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)

        alerts = []
        for doc in alerts_ref.stream():
            alert_data = doc.to_dict()
            alert_data['id'] = doc.id
            # Convertir timestamp a string para JSON
            if 'timestamp' in alert_data:
                alert_data['timestamp'] = alert_data['timestamp'].isoformat()
            alerts.append(alert_data)

        return (json.dumps(alerts), 200, headers)
    except Exception as e:
        return (json.dumps({'error': str(e)}), 500, headers)
