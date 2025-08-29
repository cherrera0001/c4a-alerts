"""
Authentication Routes for C4A Alerts API
Endpoints para autenticación, gestión de tokens y autorización.
"""

from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from typing import Optional
import logging

from c4aalerts.app.auth.jwt_auth import jwt_auth, get_current_user, UserRole, TokenPayload

logger = logging.getLogger(__name__)
router = APIRouter()

# Modelos de request/response
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

class RefreshRequest(BaseModel):
    refresh_token: str

class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenInfo(BaseModel):
    user_id: str
    username: str
    role: str
    token_type: str
    expires_at: str

class CreateAPIKeyRequest(BaseModel):
    description: str = ""

class CreateAPIKeyResponse(BaseModel):
    api_key: str
    expires_at: str
    description: str

@router.post("/login", response_model=LoginResponse, tags=["authentication"])
async def login(request: LoginRequest):
    """Autenticar usuario y obtener tokens."""
    try:
        # Autenticar usuario
        user = jwt_auth.authenticate_user(request.username, request.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Crear tokens
        access_token = jwt_auth.create_access_token(user)
        refresh_token = jwt_auth.create_refresh_token(user)

        logger.info(f"User {user.username} logged in successfully")

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=jwt_auth.access_token_expire_minutes * 60,
            user={
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value
            }
        )

    except Exception as e:
        logger.error(f"Login failed for user {request.username}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/refresh", response_model=RefreshResponse, tags=["authentication"])
async def refresh_token(request: RefreshRequest):
    """Renovar token de acceso usando refresh token."""
    try:
        # Renovar token
        access_token = jwt_auth.refresh_access_token(request.refresh_token)

        logger.info("Access token refreshed successfully")

        return RefreshResponse(
            access_token=access_token,
            expires_in=jwt_auth.access_token_expire_minutes * 60
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/logout", tags=["authentication"])
async def logout(request: Request, current_user: TokenPayload = Depends(get_current_user)):
    """Cerrar sesión y revocar tokens."""
    try:
        # Obtener token del header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            jwt_auth.revoke_token(token)

        logger.info(f"User {current_user.username} logged out")

        return {"message": "Successfully logged out"}

    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@router.get("/me", response_model=dict, tags=["authentication"])
async def get_current_user_info(current_user: TokenPayload = Depends(get_current_user)):
    """Obtener información del usuario actual."""
    user = jwt_auth.get_user_by_id(current_user.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return {
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None
    }

@router.post("/api-key", response_model=CreateAPIKeyResponse, tags=["authentication"])
async def create_api_key(
    request: CreateAPIKeyRequest,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Crear API key para acceso programático."""
    # Solo admin y analyst pueden crear API keys
    if current_user.role not in [UserRole.ADMIN.value, UserRole.ANALYST.value]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to create API keys"
        )

    try:
        user = jwt_auth.get_user_by_id(current_user.user_id)
        api_key = jwt_auth.create_api_key(user, request.description)

        # Obtener información de expiración
        payload = jwt_auth.verify_token(api_key)

        logger.info(f"API key created for user {current_user.username}")

        return CreateAPIKeyResponse(
            api_key=api_key,
            expires_at=payload.exp.isoformat(),
            description=request.description
        )

    except Exception as e:
        logger.error(f"API key creation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )

@router.get("/token-info", response_model=TokenInfo, tags=["authentication"])
async def get_token_info(current_user: TokenPayload = Depends(get_current_user)):
    """Obtener información del token actual."""
    return TokenInfo(
        user_id=current_user.user_id,
        username=current_user.username,
        role=current_user.role,
        token_type=current_user.token_type,
        expires_at=current_user.exp.isoformat()
    )

@router.delete("/revoke-all", tags=["authentication"])
async def revoke_all_tokens(current_user: TokenPayload = Depends(get_current_user)):
    """Revocar todos los tokens del usuario actual."""
    try:
        jwt_auth.revoke_all_user_tokens(current_user.user_id)

        logger.info(f"All tokens revoked for user {current_user.username}")

        return {"message": "All tokens revoked successfully"}

    except Exception as e:
        logger.error(f"Token revocation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke tokens"
        )

# Endpoint para verificar permisos
@router.get("/check-permissions", tags=["authentication"])
async def check_permissions(
    required_role: str,
    current_user: TokenPayload = Depends(get_current_user)
):
    """Verificar si el usuario tiene los permisos requeridos."""
    try:
        user_role = UserRole(current_user.role)
        required_role_enum = UserRole(required_role)

        # Verificar jerarquía de roles
        role_hierarchy = {
            UserRole.VIEWER: 1,
            UserRole.API_CLIENT: 2,
            UserRole.ANALYST: 3,
            UserRole.ADMIN: 4
        }

        has_permission = role_hierarchy.get(user_role, 0) >= role_hierarchy.get(required_role_enum, 0)

        return {
            "has_permission": has_permission,
            "user_role": current_user.role,
            "required_role": required_role,
            "user_id": current_user.user_id,
            "username": current_user.username
        }

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role specified"
        )
