#!/usr/bin/env python3
"""
🔒 SCRIPT DE PREPARACIÓN SEGURA PARA GITHUB
Verifica y prepara el proyecto para un push seguro a GitHub
"""

import os
import sys
import subprocess
import json
import re
from pathlib import Path
from datetime import datetime

class GitHubPushPreparer:
    """Preparador seguro para push a GitHub."""

    def __init__(self):
        self.project_root = Path.cwd()
        self.sensitive_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'private_key\s*=\s*["\'][^"\']+["\']',
            r'config\.json',
            r'secrets\.json',
            r'credentials\.json'
        ]

    def check_git_status(self):
        """Verificar estado de Git."""
        print("Verificando estado de Git...")

        try:
            # Verificar si estamos en un repositorio Git
            result = subprocess.run(['git', 'status'], capture_output=True, text=True)
            if result.returncode != 0:
                print("❌ No se encontró un repositorio Git. Inicializando...")
                subprocess.run(['git', 'init'])
                subprocess.run(['git', 'add', '.'])
                subprocess.run(['git', 'commit', '-m', 'Initial commit'])
                return True

            # Verificar cambios pendientes
            result = subprocess.run(['git', 'diff', '--name-only'], capture_output=True, text=True)
            if result.stdout.strip():
                print("📝 Cambios detectados:")
                for file in result.stdout.strip().split('\n'):
                    if file:
                        print(f"   - {file}")
                return True
            else:
                print("✅ No hay cambios pendientes")
                return False

        except Exception as e:
            print(f"❌ Error verificando Git: {e}")
            return False

    def check_sensitive_files(self):
        """Verificar archivos sensibles."""
        print("\nVerificando archivos sensibles...")

        sensitive_files = []
        excluded_dirs = {'venv', 'node_modules', '__pycache__', '.git'}
        excluded_files = {'prepare_github_push.py', 'simple_security_scan.py'}

        for pattern in self.sensitive_patterns:
            for file_path in self.project_root.rglob('*'):
                if file_path.is_file() and not file_path.name.startswith('.'):
                    # Excluir directorios del sistema
                    if any(excluded in str(file_path) for excluded in excluded_dirs):
                        continue

                    # Excluir archivos específicos
                    if file_path.name in excluded_files:
                        continue

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if re.search(pattern, content, re.IGNORECASE):
                                sensitive_files.append(str(file_path))
                    except:
                        continue

        if sensitive_files:
            print("⚠️  Archivos sensibles detectados:")
            for file in set(sensitive_files):
                print(f"   - {file}")
            return False
        else:
            print("✅ No se detectaron archivos sensibles")
            return True

    def check_gitignore(self):
        """Verificar .gitignore."""
        print("\n📋 Verificando .gitignore...")

        gitignore_path = self.project_root / '.gitignore'
        if not gitignore_path.exists():
            print("❌ No se encontró .gitignore")
            return False

        required_patterns = [
            '.env',
            'venv/',
            '__pycache__/',
            '*.pyc',
            '*.log',
            '*.key',
            '*.pem',
            'secrets.json',
            'config.json'
        ]

        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read()

        missing_patterns = []
        for pattern in required_patterns:
            if pattern not in gitignore_content:
                missing_patterns.append(pattern)

        if missing_patterns:
            print("⚠️  Patrones faltantes en .gitignore:")
            for pattern in missing_patterns:
                print(f"   - {pattern}")
            return False
        else:
            print("✅ .gitignore está correctamente configurado")
            return True

    def run_security_scan(self):
        """Ejecutar escaneo de seguridad."""
        print("\nEjecutando escaneo de seguridad...")

        try:
            result = subprocess.run([
                sys.executable, 'scripts/simple_security_scan.py'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print("✅ Escaneo de seguridad completado")
                return True
            else:
                print("❌ Error en escaneo de seguridad")
                print(result.stderr)
                return False
        except Exception as e:
            print(f"❌ Error ejecutando escaneo: {e}")
            return False

    def check_dependencies(self):
        """Verificar dependencias."""
        print("\n📦 Verificando dependencias...")

        requirements_files = [
            'requirements.txt',
            'pyproject.toml',
            'setup.py'
        ]

        found_files = []
        for req_file in requirements_files:
            if (self.project_root / req_file).exists():
                found_files.append(req_file)

        if found_files:
            print(f"✅ Archivos de dependencias encontrados: {', '.join(found_files)}")
            return True
        else:
            print("⚠️  No se encontraron archivos de dependencias")
            return False

    def create_commit_message(self):
        """Crear mensaje de commit."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"🔒 Security improvements and system updates - {timestamp}\n\n" \
               f"- Enhanced input validation system\n" \
               f"- Implemented automatic alerting system\n" \
               f"- Added security statistics endpoints\n" \
               f"- Fixed critical vulnerabilities\n" \
               f"- Updated .gitignore for security\n" \
               f"- Improved documentation"

    def prepare_push(self):
        """Preparar push seguro."""
        print("🚀 PREPARANDO PUSH SEGURO A GITHUB")
        print("=" * 50)

        checks = [
            ("Estado de Git", self.check_git_status),
            ("Archivos sensibles", self.check_sensitive_files),
            (".gitignore", self.check_gitignore),
            ("Escaneo de seguridad", self.run_security_scan),
            ("Dependencias", self.check_dependencies)
        ]

        all_passed = True
        for check_name, check_func in checks:
            if not check_func():
                all_passed = False
                print(f"❌ Falló: {check_name}")

        if all_passed:
            print("\n✅ TODAS LAS VERIFICACIONES PASARON")
            print("🚀 Listo para push seguro a GitHub")

            # Crear commit
            commit_message = self.create_commit_message()
            print(f"\n📝 Mensaje de commit:\n{commit_message}")

            return True
        else:
            print("\n❌ ALGUNAS VERIFICACIONES FALLARON")
            print("🔧 Corrige los problemas antes de hacer push")
            return False

    def execute_push(self):
        """Ejecutar push a GitHub."""
        print("\n🚀 EJECUTANDO PUSH A GITHUB")
        print("=" * 30)

        try:
            # Agregar todos los archivos
            print("📁 Agregando archivos...")
            subprocess.run(['git', 'add', '.'], check=True)

            # Crear commit
            print("📝 Creando commit...")
            commit_message = self.create_commit_message()
            subprocess.run(['git', 'commit', '-m', commit_message], check=True)

            # Verificar si hay un remote configurado
            result = subprocess.run(['git', 'remote', '-v'], capture_output=True, text=True)
            if not result.stdout.strip():
                print("⚠️  No hay remote configurado")
                print("💡 Configura el remote con: git remote add origin <URL>")
                return False

            # Push
            print("🚀 Haciendo push...")
            subprocess.run(['git', 'push'], check=True)

            print("✅ Push completado exitosamente")
            return True

        except subprocess.CalledProcessError as e:
            print(f"❌ Error en push: {e}")
            return False
        except Exception as e:
            print(f"❌ Error inesperado: {e}")
            return False

def main():
    """Función principal."""
    preparer = GitHubPushPreparer()

    if len(sys.argv) > 1 and sys.argv[1] == '--push':
        # Modo push directo
        if preparer.prepare_push():
            preparer.execute_push()
    else:
        # Modo verificación
        preparer.prepare_push()

if __name__ == "__main__":
    main()
