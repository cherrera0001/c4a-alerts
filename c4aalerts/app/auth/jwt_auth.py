"""
JWT Authentication System for C4A Alerts
Implementa autenticación robusta con JWT tokens, refresh tokens y gestión de sesiones.
"""

import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Union, List
from dataclasses import dataclass
from enum import Enum
import logging
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class UserRole(str, Enum):
    """Roles de usuario del sistema."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_CLIENT = "api_client"

class TokenType(str, Enum):
    """Tipos de token."""
    ACCESS = "access"
    REFRESH = "refresh"
            # ⚠️ CRÍTICO: Usar variable de entorno, NUNCA hardcodear
        API_KEY = os.getenv("API_KEY", "CHANGE_THIS_IN_PRODUCTION")

@dataclass
class User:
    """Modelo de usuario."""
    user_id: str
    username: str
    email: str
    role: UserRole
    is_active: bool = True
    created_at: datetime = None
    last_login: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class TokenPayload(BaseModel):
    """Payload del token JWT."""
    user_id: str
    username: str
    role: UserRole
    token_type: TokenType
    exp: datetime
    iat: datetime
    jti: str  # JWT ID único

class JWTAuthManager:
    """Gestor de autenticación JWT."""

    def __init__(self, secret_key: str = None, algorithm: str = "HS256"):
        self.secret_key = secret_key or self._generate_secret_key()
        self.algorithm = algorithm
        self.access_token_expire_minutes = 30  # 30 minutos
        self.refresh_token_expire_days = 7     # 7 días
        self.api_key_expire_days = 365        # 1 año

        # Almacén de tokens revocados (en producción usar Redis)
        self.revoked_tokens = set()
        self.active_refresh_tokens = {}  # user_id -> refresh_token

        # Usuarios del sistema (en producción usar base de datos)
        self.users = self._initialize_default_users()

        logger.info("JWT Authentication Manager initialized")

    def _generate_secret_key(self) -> str:
        """Generar clave secreta segura."""
        return secrets.token_urlsafe(32)

    def _initialize_default_users(self) -> Dict[str, User]:
        """Inicializar usuarios por defecto."""
        return {
            "admin": User(
                user_id="admin",
                username="admin",
                email="admin@c4a-alerts.com",
                role=UserRole.ADMIN
            ),
            "analyst": User(
                user_id="analyst",
                username="analyst",
                email="analyst@c4a-alerts.com",
                role=UserRole.ANALYST
            ),
            "viewer": User(
                user_id="viewer",
                username="viewer",
                email="viewer@c4a-alerts.com",
                role=UserRole.VIEWER
            ),
            "api_client": User(
                user_id="api_client",
                username="api_client",
                email="api@c4a-alerts.com",
                role=UserRole.API_CLIENT
            )
        }

    def create_access_token(self, user: User) -> str:
        """Crear token de acceso."""
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "token_type": TokenType.ACCESS.value,
            "exp": datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.info(f"Access token created for user: {user.username}")

        return token

    def create_refresh_token(self, user: User) -> str:
        """Crear token de refresh."""
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "token_type": TokenType.REFRESH.value,
            "exp": datetime.utcnow() + timedelta(days=self.refresh_token_expire_days),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Almacenar refresh token activo
        self.active_refresh_tokens[user.user_id] = token

        logger.info(f"Refresh token created for user: {user.username}")
        return token

    def create_api_key(self, user: User, description: str = "") -> str:
        """Crear API key para acceso programático."""
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "token_type": TokenType.API_KEY.value,
            "exp": datetime.utcnow() + timedelta(days=self.api_key_expire_days),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16),
            "description": description
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.info(f"API key created for user: {user.username}")

        return token

    def verify_token(self, token: str) -> TokenPayload:
        """Verificar y decodificar token."""
        try:
            # Verificar si el token está revocado
            if token in self.revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )

            # Decodificar token
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            # Verificar que el usuario existe y está activo
            user = self.users.get(payload["user_id"])
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

            # Verificar refresh token si es necesario
            if payload["token_type"] == TokenType.REFRESH.value:
                if self.active_refresh_tokens.get(payload["user_id"]) != token:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid refresh token"
                    )

            return TokenPayload(**payload)

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

    def refresh_access_token(self, refresh_token: str) -> str:
        """Renovar token de acceso usando refresh token."""
        payload = self.verify_token(refresh_token)

        if payload.token_type != TokenType.REFRESH.value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for refresh"
            )

        user = self.users.get(payload.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

        return self.create_access_token(user)

    def revoke_token(self, token: str) -> bool:
        """Revocar token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            self.revoked_tokens.add(token)

            # Si es refresh token, removerlo de activos
            if payload["token_type"] == TokenType.REFRESH.value:
                user_id = payload["user_id"]
                if self.active_refresh_tokens.get(user_id) == token:
                    del self.active_refresh_tokens[user_id]

            logger.info(f"Token revoked for user: {payload.get('username', 'unknown')}")
            return True

        except jwt.InvalidTokenError:
            return False

    def revoke_all_user_tokens(self, user_id: str) -> bool:
        """Revocar todos los tokens de un usuario."""
        # Remover refresh token activo
        if user_id in self.active_refresh_tokens:
            refresh_token = self.active_refresh_tokens[user_id]
            self.revoked_tokens.add(refresh_token)
            del self.active_refresh_tokens[user_id]

        logger.info(f"All tokens revoked for user: {user_id}")
        return True

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Autenticar usuario (simulado para demo)."""
        # ⚠️ SOLO PARA DESARROLLO - EN PRODUCCIÓN USAR BASE DE DATOS CON HASH
        import os
        from dotenv import load_dotenv

        load_dotenv()

        # Obtener credenciales de variables de entorno
        demo_password = os.getenv("DEMO_PASSWORD", "CHANGE_THIS_IN_PRODUCTION")

        user = self.users.get(username)
        if user and user.is_active:
            # Verificación básica (solo para desarrollo)
            if password == demo_password:
                user.last_login = datetime.now()
                return user
        return None

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Obtener usuario por ID."""
        return self.users.get(user_id)

    def require_role(self, required_roles: List[UserRole]):
        """Decorator para requerir roles específicos."""
        def decorator(func):
            async def wrapper(*args, **kwargs):
                # Esta función se implementará en el middleware
                pass
            return wrapper
        return decorator

# Instancia global del gestor de autenticación
jwt_auth = JWTAuthManager()

class JWTSecurity(HTTPBearer):
    """Clase de seguridad JWT para FastAPI."""

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        self.auth_manager = jwt_auth

    async def __call__(self, request) -> Optional[HTTPAuthorizationCredentials]:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)

        if not credentials:
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorization credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        if credentials.scheme != "Bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication scheme",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        # Verificar token
        try:
            payload = self.auth_manager.verify_token(credentials.credentials)
            request.state.user = payload
            return credentials
        except HTTPException:
            if self.auto_error:
                raise
            return None

# Función helper para obtener usuario actual
def get_current_user(request) -> TokenPayload:
    """Obtener usuario actual del request."""
    if not hasattr(request.state, 'user'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not authenticated"
        )
    return request.state.user

# Función helper para verificar roles
def require_roles(required_roles: List[UserRole]):
    """Verificar que el usuario tiene los roles requeridos."""
    def decorator(func):
        async def wrapper(request, *args, **kwargs):
            user = get_current_user(request)
            user_role = UserRole(user.role)

            if user_role not in required_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {[r.value for r in required_roles]}"
                )

            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
