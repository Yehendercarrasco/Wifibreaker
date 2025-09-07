#!/usr/bin/env python3
"""
Script de inicio para el frontend web de reportes de pentesting
"""

import sys
import os
from pathlib import Path

def main():
    """Función principal"""
    print("🌐 PENTEST REPORT VIEWER")
    print("=" * 50)
    
    # Verificar que estamos en el directorio correcto
    current_dir = Path.cwd()
    web_frontend_dir = current_dir / "web_frontend"
    
    if not web_frontend_dir.exists():
        print("❌ Error: Directorio web_frontend no encontrado")
        print(f"   Directorio actual: {current_dir}")
        print(f"   Asegúrate de ejecutar este script desde el directorio raíz del proyecto")
        sys.exit(1)
    
    # Verificar que el directorio de escaneos existe
    scans_dir = current_dir / "scans"
    if not scans_dir.exists():
        print("⚠️  Advertencia: Directorio de escaneos no encontrado")
        print(f"   Creando directorio: {scans_dir}")
        scans_dir.mkdir(exist_ok=True)
    
    # Mostrar información
    print(f"📁 Directorio de escaneos: {scans_dir}")
    print(f"🌐 Iniciando servidor web...")
    print()
    
    # Cambiar al directorio web_frontend
    os.chdir(web_frontend_dir)
    
    # Importar y ejecutar el servidor
    try:
        from server import run_server
        run_server(port=8080, host='localhost')
    except KeyboardInterrupt:
        print("\n🛑 Servidor detenido por el usuario")
    except Exception as e:
        print(f"❌ Error iniciando servidor: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
