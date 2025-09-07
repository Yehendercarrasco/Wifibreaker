#!/usr/bin/env python3
"""
Script de inicio para el servidor de reportes de pentesting
"""

import sys
import os
from pathlib import Path

# Agregar el directorio padre al path para importar módulos
sys.path.append(str(Path(__file__).parent.parent))

from web_frontend.server import run_server

def main():
    """Función principal"""
    print("🔐 PENTEST REPORT VIEWER")
    print("=" * 50)
    
    # Verificar que estamos en el directorio correcto
    current_dir = Path.cwd()
    if not (current_dir / "web_frontend").exists():
        print("❌ Error: Este script debe ejecutarse desde el directorio raíz del proyecto")
        print(f"   Directorio actual: {current_dir}")
        print(f"   Directorio esperado: {current_dir.parent}")
        sys.exit(1)
    
    # Verificar que el directorio de escaneos existe
    scans_dir = current_dir / "scans"
    if not scans_dir.exists():
        print("⚠️  Advertencia: Directorio de escaneos no encontrado")
        print(f"   Creando directorio: {scans_dir}")
        scans_dir.mkdir(exist_ok=True)
    
    # Mostrar información del servidor
    print(f"📁 Directorio de escaneos: {scans_dir}")
    print(f"🌐 Iniciando servidor web...")
    print()
    
    # Iniciar servidor
    try:
        run_server(port=8080, host='localhost')
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido por el usuario")
    except Exception as e:
        print(f"❌ Error iniciando servidor: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
