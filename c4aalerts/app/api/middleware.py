"""
Security and Observability Middleware for C4A Alerts API
Integra Zero-Trust Security y Observability con FastAPI.
"""

import time
import json
import uuid
from typing import Dict, Any, Optional
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging

from c4aalerts.app.security.zero_trust import zero_trust_security
from c4aalerts.app.monitoring.observability import observability
from c4aalerts.app.auth.jwt_auth import jwt_auth, get_current_user, UserRole

logger = logging.getLogger(__name__)

class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Middleware de autenticación JWT."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.auth_manager = jwt_auth

    async def dispatch(self, request: Request, call_next):
        """Procesar request con autenticación JWT."""
        # Endpoints públicos que no requieren autenticación
        public_endpoints = [
            '/docs', '/redoc', '/openapi.json',
            '/api/v1/auth/login', '/api/v1/auth/refresh',
            '/api/v1/health'  # Health check puede ser público
        ]

        # Verificar si es endpoint público
        if any(request.url.path.startswith(endpoint) for endpoint in public_endpoints):
            return await call_next(request)

        # Extraer token del header Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JSONResponse(
                status_code=401,
                content={
                    'error': 'Authentication required',
                    'detail': 'Bearer token required in Authorization header'
                }
            )

        token = auth_header.split(' ')[1]

        try:
            # Verificar token
            payload = self.auth_manager.verify_token(token)
            request.state.user = payload

            # Continuar con el request
            return await call_next(request)

        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={'error': 'Authentication failed', 'detail': e.detail}
            )

class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware de seguridad Zero-Trust."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.security = zero_trust_security
        self.obs = observability

    async def dispatch(self, request: Request, call_next):
        """Procesar request con seguridad y observabilidad."""
        start_time = time.time()
        trace_id = str(uuid.uuid4())

        # Extraer información del request
        client_ip = self._get_client_ip(request)
        user_id = self._extract_user_id(request)
        content = await self._extract_content(request)

        # Crear datos para análisis de seguridad
        security_data = {
            'client_id': client_ip,
            'user_id': user_id,
            'content': content,
            'action_type': self._get_action_type(request),
            'source_ip': client_ip,
            'action': f"{request.method} {request.url.path}",
            'session_id': request.headers.get('X-Session-ID', 'default'),
            'endpoint': str(request.url.path),
            'method': request.method,
            'headers': dict(request.headers),
            'query_params': dict(request.query_params)
        }

        # Análisis de seguridad
        security_result = self.security.analyze_request(security_data)

        # Logging de seguridad
        self.obs.log_security_event(
            event_type='api_request',
            risk_score=security_result['risk_score'],
            details=security_result['details'],
            user_id=user_id,
            trace_id=trace_id
        )

        # Verificar si el request está bloqueado
        if security_result['blocked']:
            logger.warning(f"Request blocked: {security_result['reason']} - Risk: {security_result['risk_score']}")

            return JSONResponse(
                status_code=403,
                content={
                    'error': 'Request blocked by security system',
                    'reason': security_result['reason'],
                    'risk_score': security_result['risk_score'],
                    'trace_id': trace_id,
                    'recommendations': security_result['recommendations']
                }
            )

        # Continuar con el request si está permitido
        try:
            with self.obs.trace_operation(
                f"{request.method} {request.url.path}",
                trace_id=trace_id,
                tags={
                    'method': request.method,
                    'path': str(request.url.path),
                    'client_ip': client_ip,
                    'user_id': user_id,
                    'risk_score': security_result['risk_score']
                }
            ) as span_id:

                # Procesar request
                response = await call_next(request)

                # Calcular duración
                duration_ms = (time.time() - start_time) * 1000

                # Logging de observabilidad
                self.obs.log_request(
                    method=request.method,
                    path=str(request.url.path),
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    user_id=user_id,
                    trace_id=trace_id,
                    span_id=span_id
                )

                # Agregar headers de observabilidad
                response.headers['X-Trace-ID'] = trace_id
                response.headers['X-Risk-Score'] = str(security_result['risk_score'])
                response.headers['X-Response-Time'] = f"{duration_ms:.2f}ms"

                return response

        except Exception as e:
            # Logging de errores
            duration_ms = (time.time() - start_time) * 1000
            error_msg = str(e)

            self.obs.log_request(
                method=request.method,
                path=str(request.url.path),
                status_code=500,
                duration_ms=duration_ms,
                user_id=user_id,
                trace_id=trace_id,
                error=error_msg
            )

            logger.error(f"Request failed: {error_msg}", exc_info=True)

            return JSONResponse(
                status_code=500,
                content={
                    'error': 'Internal server error',
                    'trace_id': trace_id,
                    'message': 'An error occurred while processing your request'
                }
            )

    def _get_client_ip(self, request: Request) -> str:
        """Obtener IP del cliente."""
        # Verificar headers de proxy
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()

        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip

        return request.client.host if request.client else 'unknown'

    def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extraer ID de usuario del request."""
        # Verificar header de autorización
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # Aquí podrías decodificar el JWT para obtener el user_id
            return None

        # Verificar query parameter
        return request.query_params.get('user_id')

    async def _extract_content(self, request: Request) -> str:
        """Extraer contenido del request."""
        try:
            if request.method in ['POST', 'PUT', 'PATCH']:
                body = await request.body()
                if body:
                    return body.decode('utf-8')
        except Exception:
            pass

        return ''

    def _get_action_type(self, request: Request) -> str:
        """Determinar tipo de acción para rate limiting."""
        path = str(request.url.path)

        if '/api/v1/malware/' in path:
            return 'malware_analysis'
        elif '/api/v1/telegram/' in path:
            return 'telegram'
        elif '/admin/' in path or request.headers.get('X-Admin-Token'):
            return 'admin'
        else:
            return 'api'

class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Middleware de observabilidad."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.obs = observability

    async def dispatch(self, request: Request, call_next):
        """Procesar request con observabilidad."""
        start_time = time.time()
        trace_id = request.headers.get('X-Trace-ID', str(uuid.uuid4()))

        # Extraer información del usuario
        user_id = self._extract_user_id(request)

        try:
            with self.obs.trace_operation(
                f"observability_{request.method}_{request.url.path}",
                trace_id=trace_id,
                tags={
                    'middleware': 'observability',
                    'method': request.method,
                    'path': str(request.url.path)
                }
            ) as span_id:

                # Procesar request
                response = await call_next(request)

                # Calcular duración
                duration_ms = (time.time() - start_time) * 1000

                # Métricas adicionales
                self.obs.metrics.set_gauge('active_requests', 1, {'path': str(request.url.path)})

                # Logging adicional si es necesario
                if response.status_code >= 400:
                    self.obs.logger.log(
                        'WARNING',
                        f"Request returned {response.status_code}",
                        trace_id=trace_id,
                        span_id=span_id,
                        user_id=user_id,
                        context={'status_code': response.status_code}
                    )

                return response

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            self.obs.logger.log(
                'ERROR',
                f"Observability middleware error: {str(e)}",
                trace_id=trace_id,
                user_id=user_id,
                error=str(e)
            )

            raise

    def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extraer ID de usuario."""
        return request.query_params.get('user_id') or request.headers.get('X-User-ID')

class MalwareAnalysisMiddleware(BaseHTTPMiddleware):
    """Middleware específico para análisis de malware."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.obs = observability

    async def dispatch(self, request: Request, call_next):
        """Procesar request con análisis de malware."""
        # Solo aplicar a endpoints de malware
        if '/api/v1/malware/' not in str(request.url.path):
            return await call_next(request)

        trace_id = request.headers.get('X-Trace-ID', str(uuid.uuid4()))
        user_id = request.query_params.get('user_id')

        try:
            # Extraer contenido para análisis
            content = await self._extract_content(request)

            if content:
                # Generar hash del contenido
                content_hash = self._generate_content_hash(content)

                # Logging de análisis de malware
                self.obs.log_malware_detection(
                    malware_type='content_analysis',
                    confidence=0.8,  # Esto vendría del análisis real
                    content_hash=content_hash,
                    user_id=user_id,
                    trace_id=trace_id
                )

            return await call_next(request)

        except Exception as e:
            self.obs.logger.log(
                'ERROR',
                f"Malware analysis middleware error: {str(e)}",
                trace_id=trace_id,
                user_id=user_id,
                error=str(e)
            )
            raise

    async def _extract_content(self, request: Request) -> str:
        """Extraer contenido para análisis."""
        try:
            if request.method in ['POST', 'PUT']:
                body = await request.body()
                if body:
                    return body.decode('utf-8')
        except Exception:
            pass

        return ''

    def _generate_content_hash(self, content: str) -> str:
        """Generar hash del contenido."""
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware de rate limiting."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.security = zero_trust_security

    async def dispatch(self, request: Request, call_next):
        """Procesar request con rate limiting."""
        client_ip = self._get_client_ip(request)
        action_type = self._get_action_type(request)

        # Verificar rate limit
        allowed, details = self.security.rate_limiter.is_allowed(client_ip, action_type)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    'error': 'Rate limit exceeded',
                    'retry_after': details.get('retry_after', 60),
                    'message': f'Too many requests. Try again in {details.get("retry_after", 60)} seconds.'
                },
                headers={'Retry-After': str(details.get('retry_after', 60))}
            )

        # Agregar headers de rate limit
        response = await call_next(request)
        response.headers['X-RateLimit-Remaining'] = str(details.get('remaining', 0))

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Obtener IP del cliente."""
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()

        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip

        return request.client.host if request.client else 'unknown'

    def _get_action_type(self, request: Request) -> str:
        """Determinar tipo de acción."""
        path = str(request.url.path)

        if '/api/v1/malware/' in path:
            return 'malware_analysis'
        elif '/api/v1/telegram/' in path:
            return 'telegram'
        elif '/admin/' in path:
            return 'admin'
        else:
            return 'api'

# Función para configurar todos los middlewares
def setup_middlewares(app: ASGIApp) -> ASGIApp:
    """Configurar todos los middlewares de seguridad y observabilidad."""

    # Orden de aplicación (de más externo a más interno)
    # Cada middleware envuelve al anterior
    wrapped_app = JWTAuthMiddleware(app)  # JWT Auth primero
    wrapped_app = SecurityMiddleware(wrapped_app)
    wrapped_app = ObservabilityMiddleware(wrapped_app)
    wrapped_app = MalwareAnalysisMiddleware(wrapped_app)
    wrapped_app = RateLimitMiddleware(wrapped_app)

    logger.info("Security and observability middlewares configured")

    return wrapped_app
