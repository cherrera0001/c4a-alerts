#!/usr/bin/env python3
"""
📊 ENDPOINTS DE ESTADÍSTICAS DE SEGURIDAD
Proporciona métricas y estadísticas de seguridad del sistema
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from pydantic import BaseModel
from datetime import datetime, timedelta

from c4aalerts.app.auth.jwt_auth import get_current_user, UserRole, require_roles
from c4aalerts.app.monitoring.alerting import alert_manager, AlertSeverity, AlertType
from c4aalerts.app.security.zero_trust import zero_trust_security
from c4aalerts.app.monitoring.observability import observability_system

router = APIRouter()

class SecurityStatsResponse(BaseModel):
    """Respuesta de estadísticas de seguridad."""
    timestamp: str
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_type: Dict[str, int]
    active_alerts: int
    resolved_alerts: int
    security_events: Dict[str, int]
    threat_detections: Dict[str, int]
    system_health: Dict[str, Any]

@router.get("/security/stats", response_model=SecurityStatsResponse)
async def get_security_stats(current_user = Depends(get_current_user)):
    """
    Obtener estadísticas de seguridad del sistema.

    Requiere rol: Admin, Analyst
    """
    # Verificar permisos
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Required roles: Admin, Analyst"
        )

    try:
        # Obtener alertas por severidad
        alerts_by_severity = {}
        for severity in AlertSeverity:
            alerts = alert_manager.get_alerts_by_severity(severity)
            alerts_by_severity[severity.value] = len(alerts)

        # Obtener alertas por tipo
        alerts_by_type = {}
        for alert_type in AlertType:
            alerts = alert_manager.get_alerts_by_type(alert_type)
            alerts_by_type[alert_type.value] = len(alerts)

        # Obtener alertas activas y resueltas
        active_alerts = len(alert_manager.get_active_alerts())
        resolved_alerts = len([a for a in alert_manager.alerts.values() if a.resolved])

        # Obtener estadísticas de seguridad
        security_stats = zero_trust_security.get_security_statistics()

        # Obtener métricas de observabilidad
        observability_data = observability_system.get_observability_data()

        return SecurityStatsResponse(
            timestamp=datetime.now().isoformat(),
            total_alerts=len(alert_manager.alerts),
            alerts_by_severity=alerts_by_severity,
            alerts_by_type=alerts_by_type,
            active_alerts=active_alerts,
            resolved_alerts=resolved_alerts,
            security_events=security_stats.get("events", {}),
            threat_detections=security_stats.get("threats", {}),
            system_health=observability_data.get("system_health", {})
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo estadísticas de seguridad: {str(e)}"
        )

@router.get("/security/alerts/active")
async def get_active_alerts(current_user = Depends(get_current_user)):
    """
    Obtener alertas activas del sistema.

    Requiere rol: Admin, Analyst
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Required roles: Admin, Analyst"
        )

    try:
        active_alerts = alert_manager.get_active_alerts()

        return {
            "status": "success",
            "total_active": len(active_alerts),
            "alerts": [
                {
                    "id": alert.id,
                    "type": alert.type.value,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat(),
                    "acknowledged": alert.acknowledged,
                    "acknowledged_by": alert.acknowledged_by,
                    "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
                }
                for alert in active_alerts
            ]
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo alertas activas: {str(e)}"
        )

@router.post("/security/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user = Depends(get_current_user)
):
    """
    Reconocer una alerta.

    Requiere rol: Admin, Analyst
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Required roles: Admin, Analyst"
        )

    try:
        alert_manager.acknowledge_alert(alert_id, current_user.username)

        return {
            "status": "success",
            "message": f"Alert {alert_id} acknowledged by {current_user.username}"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error reconociendo alerta: {str(e)}"
        )

@router.post("/security/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user = Depends(get_current_user)
):
    """
    Resolver una alerta.

    Requiere rol: Admin
    """
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Required role: Admin"
        )

    try:
        alert_manager.resolve_alert(alert_id, current_user.username)

        return {
            "status": "success",
            "message": f"Alert {alert_id} resolved by {current_user.username}"
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error resolviendo alerta: {str(e)}"
        )

@router.get("/security/threats/recent")
async def get_recent_threats(current_user = Depends(get_current_user)):
    """
    Obtener amenazas recientes detectadas.

    Requiere rol: Admin, Analyst
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Required roles: Admin, Analyst"
        )

    try:
        # Obtener alertas de las últimas 24 horas
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_alerts = [
            alert for alert in alert_manager.alerts.values()
            if alert.timestamp > cutoff_time and alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        ]

        return {
            "status": "success",
            "total_recent_threats": len(recent_alerts),
            "threats": [
                {
                    "id": alert.id,
                    "type": alert.type.value,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "timestamp": alert.timestamp.isoformat(),
                    "source": alert.source,
                    "resolved": alert.resolved
                }
                for alert in recent_alerts
            ]
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo amenazas recientes: {str(e)}"
        )

@router.get("/security/health")
async def get_security_health(current_user = Depends(get_current_user)):
    """
    Obtener estado de salud de seguridad del sistema.

    Requiere rol: Admin, Analyst
    """
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Required roles: Admin, Analyst"
        )

    try:
        # Obtener métricas de salud
        observability_data = observability_system.get_observability_data()
        security_stats = zero_trust_security.get_security_statistics()

        # Calcular score de salud
        health_score = 100

        # Reducir score por alertas críticas
        critical_alerts = len(alert_manager.get_alerts_by_severity(AlertSeverity.CRITICAL))
        health_score -= critical_alerts * 20

        # Reducir score por alertas altas
        high_alerts = len(alert_manager.get_alerts_by_severity(AlertSeverity.HIGH))
        health_score -= high_alerts * 10

        # Asegurar score mínimo
        health_score = max(health_score, 0)

        return {
            "status": "success",
            "health_score": health_score,
            "health_status": "healthy" if health_score >= 80 else "warning" if health_score >= 50 else "critical",
            "system_health": observability_data.get("system_health", {}),
            "security_metrics": security_stats,
            "active_alerts": len(alert_manager.get_active_alerts()),
            "last_updated": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo estado de salud: {str(e)}"
        )
