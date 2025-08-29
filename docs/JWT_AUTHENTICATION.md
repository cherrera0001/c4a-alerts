# 🔐 Autenticación JWT - C4A Alerts

## 📋 **Resumen**

Este documento describe la implementación completa del sistema de autenticación JWT (JSON Web Tokens) para la plataforma C4A Alerts, que proporciona seguridad robusta y control de acceso granular.

## 🎯 **Características Principales**

### **✅ Funcionalidades Implementadas**
- **Autenticación JWT** con tokens de acceso y refresh
- **Control de roles** (Admin, Analyst, Viewer, API Client)
- **API Keys** para acceso programático
- **Rate Limiting** por tipo de usuario
- **Revocación de tokens** y gestión de sesiones
- **Middleware de seguridad** integrado
- **Endpoints protegidos** con verificación automática

### **🛡️ Seguridad**
- **Tokens con expiración** (30 min access, 7 días refresh)
- **Verificación de tokens revocados**
- **Validación de roles y permisos**
- **Headers de seguridad** automáticos
- **Logging de eventos** de autenticación

## 🏗️ **Arquitectura del Sistema**

### **📁 Estructura de Archivos**
```
c4aalerts/
├── app/
│   ├── auth/
│   │   └── jwt_auth.py          # Sistema principal de autenticación
│   ├── api/
│   │   ├── routes/
│   │   │   └── auth.py          # Endpoints de autenticación
│   │   └── middleware.py        # Middleware de seguridad
│   └── security/
│       └── zero_trust.py        # Sistema Zero-Trust
```

### **🔧 Componentes Principales**

#### **1. JWTAuthManager**
- Gestión de tokens (creación, verificación, revocación)
- Autenticación de usuarios
- Control de sesiones activas
- Generación de API keys

#### **2. Middleware de Autenticación**
- Verificación automática de tokens
- Protección de endpoints
- Extracción de información de usuario
- Manejo de errores de autenticación

#### **3. Endpoints de Autenticación**
- `/api/v1/auth/login` - Inicio de sesión
- `/api/v1/auth/refresh` - Renovación de tokens
- `/api/v1/auth/logout` - Cierre de sesión
- `/api/v1/auth/me` - Información del usuario
- `/api/v1/auth/api-key` - Gestión de API keys

## 👥 **Roles y Permisos**

### **🔑 Jerarquía de Roles**
```
ADMIN (4) > ANALYST (3) > API_CLIENT (2) > VIEWER (1)
```

### **📋 Descripción de Roles**

| Rol | Permisos | Acceso |
|-----|----------|--------|
| **ADMIN** | Control total | Todos los endpoints y funciones |
| **ANALYST** | Análisis y gestión | Endpoints de análisis, creación de API keys |
| **API_CLIENT** | Acceso programático | Endpoints de API, operaciones básicas |
| **VIEWER** | Solo lectura | Endpoints de consulta, sin modificación |

### **🔒 Endpoints por Rol**

#### **Endpoints Públicos** (Sin autenticación)
- `/docs` - Documentación Swagger
- `/redoc` - Documentación ReDoc
- `/api/v1/health` - Health check
- `/api/v1/auth/login` - Login
- `/api/v1/auth/refresh` - Refresh token

#### **Endpoints Protegidos**
- **ADMIN**: Todos los endpoints
- **ANALYST**: Análisis, observabilidad, API keys
- **API_CLIENT**: Operaciones básicas, consultas
- **VIEWER**: Solo consultas y lectura

## 🚀 **Uso del Sistema**

### **1. 🔑 Inicio de Sesión**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "YOUR_SECURE_PASSWORD"
  }'
```

**Respuesta:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "user_id": "admin",
    "username": "admin",
    "email": "admin@c4a-alerts.com",
    "role": "admin"
  }
}
```

### **2. 🛡️ Uso de Token en Requests**
```bash
curl -X GET "http://localhost:8000/api/v1/observability" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
```

### **3. 🔄 Renovación de Token**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  }'
```

### **4. 🔑 Creación de API Key**
```bash
curl -X POST "http://localhost:8000/api/v1/auth/api-key" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "description": "API Key para integración"
  }'
```

## 🧪 **Pruebas del Sistema**

### **📁 Scripts de Prueba**
- `tests/test_jwt_auth.py` - Pruebas completas de autenticación

### **🚀 Ejecutar Pruebas**
```bash
# Desde el directorio raíz
python tests/test_jwt_auth.py
```

### **📊 Tipos de Pruebas**
1. **Pruebas de API Health** - Verificación de disponibilidad
2. **Pruebas de Endpoints Públicos** - Acceso sin autenticación
3. **Pruebas de Endpoints Protegidos** - Bloqueo sin autenticación
4. **Pruebas de Login** - Autenticación de usuarios
5. **Pruebas de Login Inválido** - Rechazo de credenciales incorrectas
6. **Pruebas con Autenticación** - Acceso con tokens válidos
7. **Pruebas de Refresh Token** - Renovación de tokens
8. **Pruebas de Información de Usuario** - Obtención de datos
9. **Pruebas de API Keys** - Creación y gestión
10. **Pruebas de Verificación de Permisos** - Control de roles
11. **Pruebas de Logout** - Cierre de sesión

## ⚙️ **Configuración**

### **🔧 Variables de Entorno**
```bash
# Configuración JWT (opcional, se generan automáticamente)
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256

# Configuración de expiración
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
JWT_API_KEY_EXPIRE_DAYS=365
```

### **👤 Configuración de Usuarios**
```bash
# ⚠️ IMPORTANTE: Configurar en variables de entorno
DEMO_PASSWORD=your_secure_password_here

# En producción, usar base de datos con hash de contraseñas
# NUNCA hardcodear credenciales en el código
```

## 🔒 **Seguridad y Mejores Prácticas**

### **✅ Implementado**
- **Tokens con expiración corta** (30 minutos)
- **Refresh tokens** para renovación segura
- **Revocación de tokens** al logout
- **Validación de roles** en cada endpoint
- **Rate limiting** por tipo de usuario
- **Logging de eventos** de seguridad
- **Headers de seguridad** automáticos

### **⚠️ Consideraciones de Producción**
1. **Cambiar contraseñas por defecto**
2. **Usar HTTPS** en producción
3. **Configurar secret key** segura
4. **Implementar base de datos** para usuarios
5. **Configurar Redis** para tokens revocados
6. **Monitoreo de eventos** de autenticación
7. **Backup de tokens** activos

## 🐛 **Solución de Problemas**

### **❌ Errores Comunes**

#### **1. ModuleNotFoundError: No module named 'jwt'**
```bash
# Solución: Instalar PyJWT
pip install PyJWT
```

#### **2. 401 Unauthorized**
- Verificar que el token esté presente en el header
- Verificar que el token no haya expirado
- Verificar que el token no esté revocado

#### **3. 403 Forbidden**
- Verificar que el usuario tenga el rol requerido
- Verificar permisos específicos del endpoint

#### **4. 429 Too Many Requests**
- Rate limiting activado
- Esperar antes de hacer más requests

### **🔍 Debugging**
```bash
# Verificar logs de autenticación
tail -f logs/auth.log

# Verificar estado de tokens
curl -X GET "http://localhost:8000/api/v1/auth/token-info" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📈 **Métricas y Monitoreo**

### **📊 Métricas Disponibles**
- **Login attempts** (exitosos/fallidos)
- **Token creations** por tipo
- **Token revocations**
- **Rate limiting events**
- **Permission denials**

### **📝 Logs de Eventos**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "login_success",
  "user_id": "admin",
  "ip_address": "192.168.1.100",
  "user_agent": "curl/7.68.0"
}
```

## 🔄 **Actualizaciones y Mantenimiento**

### **🔄 Proceso de Actualización**
1. **Backup** de tokens activos
2. **Migración** de configuración
3. **Pruebas** de funcionalidad
4. **Despliegue** gradual
5. **Monitoreo** post-despliegue

### **🧹 Mantenimiento**
- **Limpieza** de tokens expirados
- **Rotación** de secret keys
- **Auditoría** de permisos
- **Actualización** de roles

## 📚 **Referencias**

### **🔗 Documentación Técnica**
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)

### **📖 Mejores Prácticas**
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

---

**🎯 Estado del Sistema: ✅ IMPLEMENTADO Y FUNCIONAL**

**📅 Última Actualización:** Enero 2024
**🔧 Versión:** 2.0.0
**👨‍💻 Mantenido por:** C4A Alerts Team
