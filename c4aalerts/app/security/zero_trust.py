"""
Zero-Trust Security System for C4A Alerts
Implementa seguridad avanzada con rate limiting, detección de amenazas y análisis de comportamiento.
"""

import time
import hashlib
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import re

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Evento de seguridad registrado."""
    timestamp: datetime
    source_ip: str
    user_id: Optional[str]
    action: str
    risk_score: float
    details: Dict
    blocked: bool = False

@dataclass
class ThreatIndicator:
    """Indicador de amenaza detectado."""
    indicator_type: str  # IP, User, Behavior, Content
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL

class RateLimiter:
    """Rate limiter inteligente con diferentes estrategias."""

    def __init__(self):
        self.requests = defaultdict(deque)
        self.limits = {
            'api': {'requests': 100, 'window': 60},  # 100 requests per minute
            'malware_analysis': {'requests': 10, 'window': 60},  # 10 analysis per minute
            'telegram': {'requests': 50, 'window': 60},  # 50 messages per minute
            'admin': {'requests': 1000, 'window': 60},  # 1000 requests per minute for admin
        }

    def is_allowed(self, client_id: str, action_type: str) -> Tuple[bool, Dict]:
        """Verificar si la acción está permitida."""
        now = time.time()
        key = f"{client_id}:{action_type}"

        # Limpiar requests antiguos
        while self.requests[key] and now - self.requests[key][0] > self.limits[action_type]['window']:
            self.requests[key].popleft()

        # Verificar límite
        if len(self.requests[key]) >= self.limits[action_type]['requests']:
            return False, {
                'blocked': True,
                'reason': 'rate_limit_exceeded',
                'retry_after': int(self.limits[action_type]['window'] - (now - self.requests[key][0]))
            }

        # Registrar request
        self.requests[key].append(now)

        return True, {
            'blocked': False,
            'remaining': self.limits[action_type]['requests'] - len(self.requests[key])
        }

class ThreatDetector:
    """Detector de amenazas basado en múltiples indicadores."""

    def __init__(self):
        self.suspicious_patterns = {
            'sql_injection': [
                r"(\b(union|select|insert|update|delete|drop|create|alter)\b)",
                r"(--|#|/\*|\*/)",
                r"(\b(exec|execute|script|javascript)\b)",
            ],
            'xss': [
                r"(<script[^>]*>.*?</script>)",
                r"(javascript:.*?)",
                r"(on\w+\s*=)",
            ],
            'path_traversal': [
                r"(\.\./|\.\.\\)",
                r"(/etc/passwd|/etc/shadow)",
                r"(c:\\windows\\system32)",
            ],
            'command_injection': [
                r"(\b(wget|curl|nc|netcat|bash|sh|cmd|powershell)\b)",
                r"(\||&|;|`|\\$\(|\\$\{)",
            ]
        }

        self.known_malicious_ips = set()
        self.known_malicious_users = set()
        self.behavior_patterns = defaultdict(list)

    def analyze_content(self, content: str) -> Dict:
        """Analizar contenido en busca de amenazas."""
        threats = []
        risk_score = 0.0

        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    threats.append({
                        'type': threat_type,
                        'pattern': pattern,
                        'matches': matches,
                        'severity': self._get_threat_severity(threat_type)
                    })
                    risk_score += self._get_threat_score(threat_type)

        return {
            'threats_detected': threats,
            'risk_score': min(risk_score, 100.0),
            'is_malicious': risk_score > 50.0
        }

    def analyze_behavior(self, user_id: str, action: str, context: Dict) -> Dict:
        """Analizar comportamiento del usuario."""
        now = datetime.now()
        user_patterns = self.behavior_patterns[user_id]

        # Detectar patrones anómalos
        anomalies = []

        # Frecuencia de acciones
        recent_actions = [p for p in user_patterns if now - p['timestamp'] < timedelta(minutes=5)]
        if len(recent_actions) > 20:  # Más de 20 acciones en 5 minutos
            anomalies.append({
                'type': 'high_frequency',
                'description': f'User performed {len(recent_actions)} actions in 5 minutes',
                'severity': 'MEDIUM'
            })

        # Horarios inusuales
        hour = now.hour
        if hour < 6 or hour > 23:  # Actividad fuera de horario normal
            anomalies.append({
                'type': 'unusual_hours',
                'description': f'Activity at {hour}:00',
                'severity': 'LOW'
            })

        # Registrar comportamiento
        user_patterns.append({
            'timestamp': now,
            'action': action,
            'context': context
        })

        # Mantener solo últimos 100 patrones
        if len(user_patterns) > 100:
            user_patterns.pop(0)

        return {
            'anomalies': anomalies,
            'risk_score': len(anomalies) * 10.0,
            'is_suspicious': len(anomalies) > 0
        }

    def _get_threat_severity(self, threat_type: str) -> str:
        """Obtener severidad de la amenaza."""
        severity_map = {
            'sql_injection': 'HIGH',
            'xss': 'MEDIUM',
            'path_traversal': 'HIGH',
            'command_injection': 'CRITICAL'
        }
        return severity_map.get(threat_type, 'LOW')

    def _get_threat_score(self, threat_type: str) -> float:
        """Obtener puntuación de riesgo de la amenaza."""
        score_map = {
            'sql_injection': 30.0,
            'xss': 20.0,
            'path_traversal': 25.0,
            'command_injection': 50.0
        }
        return score_map.get(threat_type, 10.0)

class BehaviorAnalyzer:
    """Analizador de comportamiento avanzado."""

    def __init__(self):
        self.user_profiles = defaultdict(dict)
        self.session_data = defaultdict(list)
        self.risk_thresholds = {
            'low': 20.0,
            'medium': 50.0,
            'high': 80.0
        }

    def analyze_session(self, session_id: str, user_id: str, request_data: Dict) -> Dict:
        """Analizar sesión completa."""
        session = self.session_data[session_id]
        session.append({
            'timestamp': datetime.now(),
            'user_id': user_id,
            'request': request_data
        })

        # Análisis de patrones de sesión
        patterns = self._extract_session_patterns(session)
        risk_factors = self._calculate_risk_factors(session, patterns)

        return {
            'session_id': session_id,
            'patterns': patterns,
            'risk_factors': risk_factors,
            'overall_risk': sum(risk_factors.values()),
            'recommendation': self._get_recommendation(risk_factors)
        }

    def _extract_session_patterns(self, session: List) -> Dict:
        """Extraer patrones de la sesión."""
        if len(session) < 2:
            return {}

        patterns = {
            'request_frequency': len(session) / 60.0,  # requests per minute
            'unique_endpoints': len(set(s['request'].get('endpoint', '') for s in session)),
            'data_volume': sum(len(str(s['request'].get('data', ''))) for s in session),
            'time_distribution': self._analyze_time_distribution(session)
        }

        return patterns

    def _analyze_time_distribution(self, session: List) -> Dict:
        """Analizar distribución temporal de requests."""
        if len(session) < 2:
            return {}

        timestamps = [s['timestamp'] for s in session]
        intervals = []

        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)

        return {
            'avg_interval': sum(intervals) / len(intervals) if intervals else 0,
            'min_interval': min(intervals) if intervals else 0,
            'max_interval': max(intervals) if intervals else 0,
            'burst_requests': len([i for i in intervals if i < 1.0])  # requests con menos de 1 segundo
        }

    def _calculate_risk_factors(self, session: List, patterns: Dict) -> Dict:
        """Calcular factores de riesgo."""
        risk_factors = {}

        # Frecuencia alta de requests
        if patterns.get('request_frequency', 0) > 10:
            risk_factors['high_frequency'] = 20.0

        # Muchos endpoints únicos
        if patterns.get('unique_endpoints', 0) > 20:
            risk_factors['endpoint_exploration'] = 15.0

        # Volumen de datos alto
        if patterns.get('data_volume', 0) > 10000:
            risk_factors['high_data_volume'] = 10.0

        # Requests en ráfaga
        time_dist = patterns.get('time_distribution', {})
        if time_dist.get('burst_requests', 0) > 5:
            risk_factors['burst_activity'] = 25.0

        return risk_factors

    def _get_recommendation(self, risk_factors: Dict) -> str:
        """Obtener recomendación basada en factores de riesgo."""
        total_risk = sum(risk_factors.values())

        if total_risk > self.risk_thresholds['high']:
            return 'BLOCK'
        elif total_risk > self.risk_thresholds['medium']:
            return 'MONITOR_CLOSELY'
        elif total_risk > self.risk_thresholds['low']:
            return 'MONITOR'
        else:
            return 'ALLOW'

class ZeroTrustSecurity:
    """Sistema principal de seguridad Zero-Trust."""

    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.threat_detector = ThreatDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.security_events = []
        self.blocked_entities = set()

        logger.info("Zero-Trust Security System initialized")

    def analyze_request(self, request_data: Dict) -> Dict:
        """Analizar request completo para amenazas."""
        client_id = request_data.get('client_id', 'unknown')
        user_id = request_data.get('user_id')
        content = request_data.get('content', '')
        action_type = request_data.get('action_type', 'api')

        # 1. Rate Limiting
        rate_limit_result = self.rate_limiter.is_allowed(client_id, action_type)
        if rate_limit_result[0] is False:
            return self._create_security_response(
                blocked=True,
                reason='rate_limit_exceeded',
                risk_score=100.0,
                details=rate_limit_result[1]
            )

        # 2. Content Analysis
        content_analysis = self.threat_detector.analyze_content(content)

        # 3. Behavior Analysis
        behavior_analysis = self.threat_detector.analyze_behavior(
            user_id,
            request_data.get('action', 'unknown'),
            request_data
        )

        # 4. Session Analysis
        session_analysis = self.behavior_analyzer.analyze_session(
            request_data.get('session_id', 'default'),
            user_id,
            request_data
        )

        # 5. Calculate Overall Risk
        total_risk = (
            content_analysis['risk_score'] * 0.4 +
            behavior_analysis['risk_score'] * 0.3 +
            session_analysis['overall_risk'] * 0.3
        )

        # 6. Decision Making
        should_block = (
            content_analysis['is_malicious'] or
            behavior_analysis['is_suspicious'] or
            total_risk > 70.0 or
            client_id in self.blocked_entities
        )

        # 7. Log Security Event
        security_event = SecurityEvent(
            timestamp=datetime.now(),
            source_ip=request_data.get('source_ip', 'unknown'),
            user_id=user_id,
            action=request_data.get('action', 'unknown'),
            risk_score=total_risk,
            details={
                'content_analysis': content_analysis,
                'behavior_analysis': behavior_analysis,
                'session_analysis': session_analysis,
                'rate_limit': rate_limit_result[1]
            },
            blocked=should_block
        )

        self.security_events.append(security_event)

        # 8. Update Blocked Entities
        if should_block:
            self.blocked_entities.add(client_id)
            if user_id:
                self.blocked_entities.add(user_id)

        return self._create_security_response(
            blocked=should_block,
            reason='threat_detected' if should_block else 'allowed',
            risk_score=total_risk,
            details={
                'content_threats': content_analysis['threats_detected'],
                'behavior_anomalies': behavior_analysis['anomalies'],
                'session_risk': session_analysis['overall_risk'],
                'recommendation': session_analysis['recommendation']
            }
        )

    def _create_security_response(self, blocked: bool, reason: str, risk_score: float, details: Dict) -> Dict:
        """Crear respuesta de seguridad estandarizada."""
        return {
            'allowed': not blocked,
            'blocked': blocked,
            'reason': reason,
            'risk_score': risk_score,
            'timestamp': datetime.now().isoformat(),
            'details': details,
            'recommendations': self._get_security_recommendations(risk_score, details)
        }

    def _get_security_recommendations(self, risk_score: float, details: Dict) -> List[str]:
        """Obtener recomendaciones de seguridad."""
        recommendations = []

        if risk_score > 80:
            recommendations.append("BLOCK_IP_TEMPORARILY")
            recommendations.append("NOTIFY_SECURITY_TEAM")
        elif risk_score > 60:
            recommendations.append("MONITOR_CLOSELY")
            recommendations.append("ENABLE_ADDITIONAL_LOGGING")
        elif risk_score > 40:
            recommendations.append("INCREASE_MONITORING")

        if details.get('content_threats'):
            recommendations.append("SCAN_FOR_MALWARE")

        if details.get('behavior_anomalies'):
            recommendations.append("ANALYZE_USER_BEHAVIOR")

        return recommendations

    def get_security_stats(self) -> Dict:
        """Obtener estadísticas de seguridad."""
        total_events = len(self.security_events)
        blocked_events = len([e for e in self.security_events if e.blocked])

        return {
            'total_events': total_events,
            'blocked_events': blocked_events,
            'block_rate': (blocked_events / total_events * 100) if total_events > 0 else 0,
            'blocked_entities': len(self.blocked_entities),
            'avg_risk_score': sum(e.risk_score for e in self.security_events) / total_events if total_events > 0 else 0,
            'recent_threats': len([e for e in self.security_events[-100:] if e.risk_score > 50])
        }

# Instancia global del sistema de seguridad
zero_trust_security = ZeroTrustSecurity()
