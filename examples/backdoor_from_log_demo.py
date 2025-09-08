#!/usr/bin/env python3
"""
Demo de Carga de Backdoors desde Log Específico
Ejemplo de cómo usar el módulo de gestión de backdoors con un log específico
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.backdoor_management import BackdoorManagementModule
from modules.backdoor_menu import BackdoorMenu
import logging
import json

def setup_logging():
    """Configurar logging para el demo"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('backdoor_from_log_demo.log')
        ]
    )
    return logging.getLogger(__name__)

def create_example_log():
    """Crear un log de ejemplo basado en el reporte"""
    log_content = """
2024-01-06 20:54:31 - INFO - BACKDOOR_INSTALLED: IP:192.168.1.5 TYPE:netcat PORT:4444 USER:admin PASS:admin123
2024-01-06 20:54:32 - INFO - BACKDOOR_INSTALLED: IP:192.168.1.7 TYPE:powershell PORT:8080 USER:svc_windowsupdate PASS:W1nd0ws_Upd@te_2024!
2024-01-06 20:54:33 - INFO - COMPROMISE_SUCCESS: IP:192.168.1.12 TYPE:lateral_movement METHOD:eternalblue USER:admin PASS:admin
2024-01-06 20:54:34 - INFO - REMOTE_ACCESS_ESTABLISHED: IP:192.168.1.218 TYPE:camera PORT:80 USER:admin PASS:admin
2024-01-06 20:54:35 - INFO - REMOTE_ACCESS_ESTABLISHED: IP:192.168.1.7 TYPE:database PORT:3306 USER:root PASS:root
2024-01-06 20:54:36 - INFO - BACKDOOR_INSTALLED: IP:192.168.1.17 TYPE:python PORT:9999 USER:admin PASS:admin
"""
    
    # Crear directorio de logs si no existe
    os.makedirs("scans/logs", exist_ok=True)
    
    # Escribir log de ejemplo
    with open("scans/logs/pentest_example.log", "w") as f:
        f.write(log_content)
    
    print("✅ Log de ejemplo creado: scans/logs/pentest_example.log")

def create_example_evidence():
    """Crear evidencia de ejemplo"""
    # Crear directorio de evidencia
    os.makedirs("scans/persistence", exist_ok=True)
    
    # Evidencia de persistencia
    persistence_evidence = {
        "backdoors": [
            {
                "type": "netcat",
                "ip": "192.168.1.5",
                "port": "4444",
                "username": "admin",
                "password": "admin123",
                "timestamp": 1757184150.567725
            },
            {
                "type": "powershell",
                "ip": "192.168.1.7",
                "port": "8080",
                "username": "svc_windowsupdate",
                "password": "W1nd0ws_Upd@te_2024!",
                "timestamp": 1757184150.567725
            }
        ]
    }
    
    with open("scans/persistence/persistence_results.json", "w") as f:
        json.dump(persistence_evidence, f, indent=2)
    
    # Evidencia de IoT
    os.makedirs("scans/iot_exploitation", exist_ok=True)
    
    iot_evidence = {
        "remote_access_established": [
            {
                "device_type": "camera",
                "ip": "192.168.1.218",
                "port": "80",
                "username": "admin",
                "password": "admin",
                "access_script": "camera_access_192.168.1.218.sh",
                "timestamp": 1757184150.567725
            }
        ]
    }
    
    with open("scans/iot_exploitation/iot_exploitation_results.json", "w") as f:
        json.dump(iot_evidence, f, indent=2)
    
    # Evidencia de SQL
    os.makedirs("scans/sql_exfiltration", exist_ok=True)
    
    sql_evidence = {
        "remote_connections": [
            {
                "host": "192.168.1.7",
                "port": "3306",
                "credentials": {
                    "username": "root",
                    "password": "root"
                },
                "connection_script": "db_connection_192.168.1.7_mysql.sh",
                "timestamp": 1757184150.567725
            }
        ]
    }
    
    with open("scans/sql_exfiltration/sql_exfiltration_results.json", "w") as f:
        json.dump(sql_evidence, f, indent=2)
    
    print("✅ Evidencia de ejemplo creada en directorios scans/")

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
    
    logger.info("🚀 INICIANDO DEMO DE CARGA DE BACKDOORS DESDE LOG")
    
    # Crear archivos de ejemplo
    create_example_log()
    create_example_evidence()
    
    # Crear instancia del módulo
    backdoor_module = BackdoorManagementModule(config, logger)
    backdoor_menu = BackdoorMenu(config, logger)
    
    # 1. Cargar desde log específico
    logger.info("📂 Fase 1: Cargando backdoors desde log específico...")
    log_file = "scans/logs/pentest_example.log"
    backdoors_from_log = backdoor_module.discover_existing_backdoors(log_file)
    
    logger.info(f"✅ Cargados {len(backdoors_from_log)} backdoors desde log")
    for i, backdoor in enumerate(backdoors_from_log, 1):
        logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
    
    # 2. Cargar desde evidencia de persistencia
    logger.info("📂 Fase 2: Cargando backdoors desde evidencia de persistencia...")
    persistence_file = "scans/persistence/persistence_results.json"
    backdoors_from_persistence = backdoor_module.discover_existing_backdoors(persistence_file)
    
    logger.info(f"✅ Cargados {len(backdoors_from_persistence)} backdoors desde evidencia de persistencia")
    for i, backdoor in enumerate(backdoors_from_persistence, 1):
        logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
    
    # 3. Cargar desde evidencia de IoT
    logger.info("📂 Fase 3: Cargando accesos desde evidencia de IoT...")
    iot_file = "scans/iot_exploitation/iot_exploitation_results.json"
    backdoors_from_iot = backdoor_module.discover_existing_backdoors(iot_file)
    
    logger.info(f"✅ Cargados {len(backdoors_from_iot)} accesos desde evidencia de IoT")
    for i, backdoor in enumerate(backdoors_from_iot, 1):
        logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
    
    # 4. Cargar desde evidencia de SQL
    logger.info("📂 Fase 4: Cargando conexiones desde evidencia de SQL...")
    sql_file = "scans/sql_exfiltration/sql_exfiltration_results.json"
    backdoors_from_sql = backdoor_module.discover_existing_backdoors(sql_file)
    
    logger.info(f"✅ Cargados {len(backdoors_from_sql)} conexiones desde evidencia de SQL")
    for i, backdoor in enumerate(backdoors_from_sql, 1):
        logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
    
    # 5. Descubrir desde todos los logs
    logger.info("🔍 Fase 5: Descubriendo backdoors desde todos los logs...")
    all_backdoors = backdoor_module.discover_existing_backdoors()
    
    logger.info(f"✅ Descubiertos {len(all_backdoors)} backdoors en total")
    
    # 6. Mostrar resumen por tipo
    logger.info("📊 RESUMEN POR TIPO:")
    backdoor_types = {}
    for backdoor in all_backdoors:
        backdoor_type = backdoor.get('type', 'unknown')
        if backdoor_type not in backdoor_types:
            backdoor_types[backdoor_type] = 0
        backdoor_types[backdoor_type] += 1
    
    for backdoor_type, count in backdoor_types.items():
        logger.info(f"   - {backdoor_type}: {count} backdoors")
    
    # 7. Mostrar comandos de acceso
    logger.info("🔧 COMANDOS DE ACCESO DISPONIBLES:")
    for i, backdoor in enumerate(all_backdoors, 1):
        logger.info(f"   {i}. {backdoor['type']} en {backdoor['ip']}:{backdoor.get('port', 'N/A')}")
        if 'username' in backdoor:
            logger.info(f"      Usuario: {backdoor['username']}")
        if 'password' in backdoor:
            logger.info(f"      Contraseña: {backdoor['password']}")
        if 'access_script' in backdoor:
            logger.info(f"      Script: ./{backdoor['access_script']}")
        elif 'connection_script' in backdoor:
            logger.info(f"      Script: ./{backdoor['connection_script']}")
        logger.info("")
    
    logger.info("✅ DEMO COMPLETADO")
    logger.info("💡 Ahora puedes usar estos backdoors para escaneos remotos")

if __name__ == "__main__":
    main()
