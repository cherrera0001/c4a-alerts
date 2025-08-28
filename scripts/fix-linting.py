#!/usr/bin/env python3
"""
Script para arreglar automáticamente los errores de linting
"""

import os
import subprocess
import sys

def run_command(cmd, description):
    """Ejecutar comando y mostrar resultado"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} completado")
            if result.stdout:
                print(result.stdout)
        else:
            print(f"❌ {description} falló")
            if result.stderr:
                print(result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error ejecutando {description}: {e}")
        return False

def main():
    """Función principal"""
    print("🔧 Arreglando errores de linting...")
    print("=" * 50)

    # Verificar que estamos en el directorio correcto
    if not os.path.exists("pyproject.toml"):
        print("❌ No se encontró pyproject.toml. Ejecuta desde el directorio raíz del proyecto.")
        sys.exit(1)

    # 1. Arreglar imports y formato con ruff
    success = run_command(
        "ruff check --fix c4aalerts/ tests/",
        "Arreglando imports y formato con ruff"
    )

    # 2. Arreglar tipos con ruff
    success &= run_command(
        "ruff check --fix --select UP c4aalerts/ tests/",
        "Arreglando tipos deprecados"
    )

    # 3. Verificar que no hay errores restantes
    success &= run_command(
        "ruff check c4aalerts/ tests/",
        "Verificando errores restantes"
    )

    if success:
        print("\n✅ Todos los errores de linting han sido arreglados!")
    else:
        print("\n❌ Algunos errores no pudieron ser arreglados automáticamente")
        print("Revisa manualmente los archivos mencionados")

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
