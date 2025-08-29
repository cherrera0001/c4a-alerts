#!/usr/bin/env python3
"""
Test Script for JWT Authentication System
Prueba la implementación completa de autenticación JWT.
"""

import requests
import json
import time
from typing import Dict, Any

class JWTAuthTester:
    """Tester para el sistema de autenticación JWT."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.access_token = None
        self.refresh_token = None
        self.test_results = []

    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Registrar resultado de prueba."""
        status = "✅ PASÓ" if success else "❌ FALLÓ"
        print(f"{status} {test_name}")
        if details:
            print(f"   📝 {details}")

        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })

    def test_api_health(self):
        """Probar que la API esté funcionando."""
        try:
            response = self.session.get(f"{self.base_url}/api/v1/health")
            if response.status_code == 200:
                self.log_test("API Health Check", True, "API respondiendo correctamente")
                return True
            else:
                self.log_test("API Health Check", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test("API Health Check", False, f"Error: {str(e)}")
            return False

    def test_public_endpoints(self):
        """Probar endpoints públicos."""
        public_endpoints = [
            "/docs",
            "/redoc",
            "/api/v1/health"
        ]

        for endpoint in public_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code in [200, 302]:  # 302 para redirects
                    self.log_test(f"Public Endpoint: {endpoint}", True)
                else:
                    self.log_test(f"Public Endpoint: {endpoint}", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"Public Endpoint: {endpoint}", False, f"Error: {str(e)}")

    def test_protected_endpoints_without_auth(self):
        """Probar endpoints protegidos sin autenticación."""
        protected_endpoints = [
            "/api/v1/observability",
            "/api/v1/security/stats",
            "/api/v1/malware/analyze",
            "/api/v1/workers/status"
        ]

        for endpoint in protected_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code == 401:
                    self.log_test(f"Protected Endpoint (no auth): {endpoint}", True, "Correctamente bloqueado")
                else:
                    self.log_test(f"Protected Endpoint (no auth): {endpoint}", False, f"Debería ser 401, fue {response.status_code}")
            except Exception as e:
                self.log_test(f"Protected Endpoint (no auth): {endpoint}", False, f"Error: {str(e)}")

    def test_login(self):
        """Probar login de usuarios."""
        users = [
            {"username": "admin", "password": "password123", "role": "admin"},
            {"username": "analyst", "password": "password123", "role": "analyst"},
            {"username": "viewer", "password": "password123", "role": "viewer"},
            {"username": "api_client", "password": "password123", "role": "api_client"}
        ]

        for user in users:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/v1/auth/login",
                    json={"username": user["username"], "password": user["password"]}
                )

                if response.status_code == 200:
                    data = response.json()
                    if "access_token" in data and "refresh_token" in data:
                        self.log_test(f"Login: {user['username']}", True, f"Role: {user['role']}")

                        # Guardar tokens para el primer usuario (admin)
                        if user["username"] == "admin":
                            self.access_token = data["access_token"]
                            self.refresh_token = data["refresh_token"]
                    else:
                        self.log_test(f"Login: {user['username']}", False, "Tokens no encontrados en respuesta")
                else:
                    self.log_test(f"Login: {user['username']}", False, f"Status: {response.status_code}")

            except Exception as e:
                self.log_test(f"Login: {user['username']}", False, f"Error: {str(e)}")

    def test_invalid_login(self):
        """Probar login con credenciales inválidas."""
        invalid_credentials = [
            {"username": "admin", "password": "wrongpassword"},
            {"username": "nonexistent", "password": "password123"},
            {"username": "", "password": "password123"},
            {"username": "admin", "password": ""}
        ]

        for creds in invalid_credentials:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/v1/auth/login",
                    json=creds
                )

                if response.status_code == 401:
                    self.log_test(f"Invalid Login: {creds['username']}", True, "Correctamente rechazado")
                else:
                    self.log_test(f"Invalid Login: {creds['username']}", False, f"Debería ser 401, fue {response.status_code}")

            except Exception as e:
                self.log_test(f"Invalid Login: {creds['username']}", False, f"Error: {str(e)}")

    def test_protected_endpoints_with_auth(self):
        """Probar endpoints protegidos con autenticación."""
        if not self.access_token:
            self.log_test("Protected Endpoints with Auth", False, "No hay token de acceso")
            return

        headers = {"Authorization": f"Bearer {self.access_token}"}
        protected_endpoints = [
            "/api/v1/observability",
            "/api/v1/security/stats",
            "/api/v1/auth/me",
            "/api/v1/auth/token-info"
        ]

        for endpoint in protected_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}", headers=headers)
                if response.status_code == 200:
                    self.log_test(f"Protected Endpoint (with auth): {endpoint}", True)
                elif response.status_code == 403:
                    self.log_test(f"Protected Endpoint (with auth): {endpoint}", True, "Acceso denegado por permisos (esperado)")
                else:
                    self.log_test(f"Protected Endpoint (with auth): {endpoint}", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"Protected Endpoint (with auth): {endpoint}", False, f"Error: {str(e)}")

    def test_token_refresh(self):
        """Probar renovación de token."""
        if not self.refresh_token:
            self.log_test("Token Refresh", False, "No hay refresh token")
            return

        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/refresh",
                json={"refresh_token": self.refresh_token}
            )

            if response.status_code == 200:
                data = response.json()
                if "access_token" in data:
                    self.log_test("Token Refresh", True, "Token renovado correctamente")
                    self.access_token = data["access_token"]  # Actualizar token
                else:
                    self.log_test("Token Refresh", False, "Nuevo access_token no encontrado")
            else:
                self.log_test("Token Refresh", False, f"Status: {response.status_code}")

        except Exception as e:
            self.log_test("Token Refresh", False, f"Error: {str(e)}")

    def test_user_info(self):
        """Probar obtención de información de usuario."""
        if not self.access_token:
            self.log_test("User Info", False, "No hay token de acceso")
            return

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            response = self.session.get(f"{self.base_url}/api/v1/auth/me", headers=headers)

            if response.status_code == 200:
                data = response.json()
                if "username" in data and "role" in data:
                    self.log_test("User Info", True, f"Usuario: {data['username']}, Role: {data['role']}")
                else:
                    self.log_test("User Info", False, "Información de usuario incompleta")
            else:
                self.log_test("User Info", False, f"Status: {response.status_code}")

        except Exception as e:
            self.log_test("User Info", False, f"Error: {str(e)}")

    def test_api_key_creation(self):
        """Probar creación de API key."""
        if not self.access_token:
            self.log_test("API Key Creation", False, "No hay token de acceso")
            return

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/auth/api-key",
                json={"description": "Test API Key"},
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                if "api_key" in data:
                    self.log_test("API Key Creation", True, "API key creada correctamente")
                    return data["api_key"]
                else:
                    self.log_test("API Key Creation", False, "API key no encontrada en respuesta")
            elif response.status_code == 403:
                self.log_test("API Key Creation", True, "Acceso denegado por permisos (esperado para algunos roles)")
            else:
                self.log_test("API Key Creation", False, f"Status: {response.status_code}")

        except Exception as e:
            self.log_test("API Key Creation", False, f"Error: {str(e)}")

        return None

    def test_logout(self):
        """Probar logout."""
        if not self.access_token:
            self.log_test("Logout", False, "No hay token de acceso")
            return

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            response = self.session.post(f"{self.base_url}/api/v1/auth/logout", headers=headers)

            if response.status_code == 200:
                self.log_test("Logout", True, "Logout exitoso")
                # Limpiar tokens
                self.access_token = None
                self.refresh_token = None
            else:
                self.log_test("Logout", False, f"Status: {response.status_code}")

        except Exception as e:
            self.log_test("Logout", False, f"Error: {str(e)}")

    def test_permission_check(self):
        """Probar verificación de permisos."""
        if not self.access_token:
            self.log_test("Permission Check", False, "No hay token de acceso")
            return

        headers = {"Authorization": f"Bearer {self.access_token}"}

        # Probar diferentes roles requeridos
        required_roles = ["viewer", "analyst", "admin"]

        for role in required_roles:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/v1/auth/check-permissions?required_role={role}",
                    headers=headers
                )

                if response.status_code == 200:
                    data = response.json()
                    if "has_permission" in data:
                        self.log_test(f"Permission Check: {role}", True, f"Has permission: {data['has_permission']}")
                    else:
                        self.log_test(f"Permission Check: {role}", False, "Respuesta incompleta")
                else:
                    self.log_test(f"Permission Check: {role}", False, f"Status: {response.status_code}")

            except Exception as e:
                self.log_test(f"Permission Check: {role}", False, f"Error: {str(e)}")

    def run_all_tests(self):
        """Ejecutar todas las pruebas."""
        print("🔐 INICIANDO PRUEBAS DE AUTENTICACIÓN JWT")
        print("=" * 50)

        # Pruebas básicas
        if not self.test_api_health():
            print("❌ API no está disponible. Deteniendo pruebas.")
            return

        self.test_public_endpoints()
        self.test_protected_endpoints_without_auth()

        # Pruebas de autenticación
        print("\n🔑 PRUEBAS DE AUTENTICACIÓN")
        print("-" * 30)
        self.test_login()
        self.test_invalid_login()

        # Pruebas con autenticación
        print("\n🛡️ PRUEBAS CON AUTENTICACIÓN")
        print("-" * 30)
        self.test_protected_endpoints_with_auth()
        self.test_user_info()
        self.test_token_refresh()
        self.test_api_key_creation()
        self.test_permission_check()

        # Pruebas de logout
        print("\n🚪 PRUEBAS DE LOGOUT")
        print("-" * 30)
        self.test_logout()

        # Resumen
        print("\n📊 RESUMEN DE PRUEBAS")
        print("=" * 50)
        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)

        print(f"✅ Pruebas pasadas: {passed}/{total}")
        print(f"❌ Pruebas fallidas: {total - passed}/{total}")
        print(f"📈 Porcentaje de éxito: {(passed/total)*100:.1f}%")

        if total - passed > 0:
            print("\n🔍 PRUEBAS FALLIDAS:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"   ❌ {result['test']}: {result['details']}")

if __name__ == "__main__":
    tester = JWTAuthTester()
    tester.run_all_tests()
