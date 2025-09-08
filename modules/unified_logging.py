"""
Sistema de Logging Unificado
Un solo JSON con toda la información del escaneo
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

class UnifiedLoggingSystem:
    """Sistema de logging unificado - un solo JSON con toda la información"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        
        # Directorio base de escaneos
        self.scans_dir = Path("scans")
        self.scans_dir.mkdir(exist_ok=True)
        
        # Estructura del JSON unificado
        self.scan_data = {
            "metadata": {
                "scan_id": "",
                "mote": "",
                "created_at": "",
                "completed_at": "",
                "is_cold_pentest": False,
                "target_network": "",
                "status": "in_progress"
            },
            "network_map": {
                "public_ips": [],
                "private_ips": [],
                "devices": [],
                "topology": {}
            },
            "credentials": {
                "captured_passwords": [],
                "default_credentials": [],
                "cracked_hashes": []
            },
            "persistence": {
                "backdoors": [],
                "users_created": [],
                "services_installed": [],
                "scheduled_tasks": [],
                "registry_modifications": []
            },
            "connections": {
                "ssh_access": [],
                "rdp_access": [],
                "smb_access": [],
                "database_connections": [],
                "remote_access": []
            },
            "compromised_systems": {
                "lateral_movement": [],
                "privilege_escalation": [],
                "exploited_vulnerabilities": []
            },
            "iot_devices": {
                "cameras": [],
                "routers": [],
                "other_devices": []
            },
            "exfiltration": {
                "data_size": 0,
                "files_count": 0,
                "sensitive_data": []
            },
            "server_configs": {
                "backdoor_servers": [],
                "exfiltration_servers": [],
                "c2_servers": []
            },
            "phases_completed": [],
            "timestamp": time.time()
        }
        
        self.current_scan_dir = None
        self.scan_data_file = None
    
    def initialize_scan(self, scan_id: str, mote: str, target_network: str, is_cold_pentest: bool = False) -> None:
        """Inicializar nuevo escaneo"""
        self.logger.info(f"🎯 Inicializando escaneo: {mote}")
        
        # Crear directorio del escaneo
        self.current_scan_dir = self.scans_dir / mote
        self.current_scan_dir.mkdir(exist_ok=True)
        
        # Crear subcarpetas
        (self.current_scan_dir / "exfiltraciones").mkdir(exist_ok=True)
        (self.current_scan_dir / "pruebas").mkdir(exist_ok=True)
        
        # Configurar archivo de datos
        self.scan_data_file = self.current_scan_dir / "scan_data.json"
        
        # Inicializar datos del escaneo
        self.scan_data["metadata"].update({
            "scan_id": scan_id,
            "mote": mote,
            "created_at": datetime.now().isoformat(),
            "target_network": target_network,
            "is_cold_pentest": is_cold_pentest,
            "status": "in_progress"
        })
        
        # Guardar archivo inicial
        self.save_scan_data()
        
        self.logger.info(f"✅ Escaneo inicializado: {self.current_scan_dir}")
    
    def add_network_discovery(self, hosts: List[Dict[str, Any]]) -> None:
        """Agregar descubrimiento de red"""
        self.logger.info(f"🌐 Agregando {len(hosts)} hosts al mapa de red")
        
        for host in hosts:
            if host.get('ip'):
                if self._is_public_ip(host['ip']):
                    self.scan_data["network_map"]["public_ips"].append(host)
                else:
                    self.scan_data["network_map"]["private_ips"].append(host)
                
                # Agregar como dispositivo
                device_info = {
                    "ip": host['ip'],
                    "hostname": host.get('hostname', ''),
                    "os": host.get('os', ''),
                    "services": host.get('services', []),
                    "ports": host.get('ports', []),
                    "vendor": host.get('vendor', ''),
                    "discovered_at": datetime.now().isoformat()
                }
                self.scan_data["network_map"]["devices"].append(device_info)
        
        self.save_scan_data()
    
    def add_credentials(self, credentials: List[Dict[str, Any]], credential_type: str = "captured") -> None:
        """Agregar credenciales obtenidas"""
        self.logger.info(f"🔑 Agregando {len(credentials)} credenciales ({credential_type})")
        
        for cred in credentials:
            cred_info = {
                "username": cred.get('username', ''),
                "password": cred.get('password', ''),
                "hash": cred.get('hash', ''),
                "target": cred.get('target', ''),
                "service": cred.get('service', ''),
                "method": cred.get('method', ''),
                "captured_at": datetime.now().isoformat()
            }
            
            if credential_type == "captured":
                self.scan_data["credentials"]["captured_passwords"].append(cred_info)
            elif credential_type == "default":
                self.scan_data["credentials"]["default_credentials"].append(cred_info)
            elif credential_type == "cracked":
                self.scan_data["credentials"]["cracked_hashes"].append(cred_info)
        
        self.save_scan_data()
    
    def add_persistence(self, persistence_data: Dict[str, Any]) -> None:
        """Agregar datos de persistencia"""
        self.logger.info("🔒 Agregando datos de persistencia")
        
        # Backdoors
        if "backdoors" in persistence_data:
            for backdoor in persistence_data["backdoors"]:
                backdoor_info = {
                    "id": backdoor.get('id', ''),
                    "type": backdoor.get('type', ''),
                    "host": backdoor.get('host', ''),
                    "port": backdoor.get('port', ''),
                    "username": backdoor.get('username', ''),
                    "password": backdoor.get('password', ''),
                    "access_script": backdoor.get('access_script', ''),
                    "created_at": datetime.now().isoformat(),
                    "status": "active"
                }
                self.scan_data["persistence"]["backdoors"].append(backdoor_info)
        
        # Usuarios creados
        if "users_created" in persistence_data:
            for user in persistence_data["users_created"]:
                user_info = {
                    "username": user.get('username', ''),
                    "password": user.get('password', ''),
                    "host": user.get('host', ''),
                    "groups": user.get('groups', []),
                    "created_at": datetime.now().isoformat()
                }
                self.scan_data["persistence"]["users_created"].append(user_info)
        
        # Servicios instalados
        if "services" in persistence_data:
            for service in persistence_data["services"]:
                service_info = {
                    "name": service.get('name', ''),
                    "host": service.get('host', ''),
                    "port": service.get('port', ''),
                    "command": service.get('command', ''),
                    "created_at": datetime.now().isoformat()
                }
                self.scan_data["persistence"]["services_installed"].append(service_info)
        
        self.save_scan_data()
    
    def add_connection(self, connection_data: Dict[str, Any]) -> None:
        """Agregar conexión establecida"""
        self.logger.info(f"🔗 Agregando conexión: {connection_data.get('type', 'unknown')}")
        
        connection_info = {
            "type": connection_data.get('type', ''),
            "host": connection_data.get('host', ''),
            "port": connection_data.get('port', ''),
            "username": connection_data.get('username', ''),
            "password": connection_data.get('password', ''),
            "method": connection_data.get('method', ''),
            "established_at": datetime.now().isoformat(),
            "status": "active"
        }
        
        # Agregar al tipo correspondiente
        conn_type = connection_data.get('type', '').lower()
        if 'ssh' in conn_type:
            self.scan_data["connections"]["ssh_access"].append(connection_info)
        elif 'rdp' in conn_type:
            self.scan_data["connections"]["rdp_access"].append(connection_info)
        elif 'smb' in conn_type:
            self.scan_data["connections"]["smb_access"].append(connection_info)
        elif 'database' in conn_type or 'sql' in conn_type:
            self.scan_data["connections"]["database_connections"].append(connection_info)
        else:
            self.scan_data["connections"]["remote_access"].append(connection_info)
        
        self.save_scan_data()
    
    def add_compromised_system(self, system_data: Dict[str, Any]) -> None:
        """Agregar sistema comprometido"""
        self.logger.info(f"💻 Agregando sistema comprometido: {system_data.get('host', 'unknown')}")
        
        system_info = {
            "host": system_data.get('host', ''),
            "ip": system_data.get('ip', ''),
            "os": system_data.get('os', ''),
            "username": system_data.get('username', ''),
            "password": system_data.get('password', ''),
            "privileges": system_data.get('privileges', ''),
            "compromise_method": system_data.get('method', ''),
            "compromised_at": datetime.now().isoformat(),
            "status": "compromised"
        }
        
        self.scan_data["compromised_systems"]["lateral_movement"].append(system_info)
        self.save_scan_data()
    
    def add_iot_device(self, device_data: Dict[str, Any]) -> None:
        """Agregar dispositivo IoT comprometido"""
        self.logger.info(f"📹 Agregando dispositivo IoT: {device_data.get('type', 'unknown')}")
        
        device_info = {
            "ip": device_data.get('ip', ''),
            "type": device_data.get('type', ''),
            "vendor": device_data.get('vendor', ''),
            "model": device_data.get('model', ''),
            "username": device_data.get('username', ''),
            "password": device_data.get('password', ''),
            "access_method": device_data.get('access_method', ''),
            "compromised_at": datetime.now().isoformat(),
            "status": "compromised"
        }
        
        device_type = device_data.get('type', '').lower()
        if 'camera' in device_type:
            self.scan_data["iot_devices"]["cameras"].append(device_info)
        elif 'router' in device_type:
            self.scan_data["iot_devices"]["routers"].append(device_info)
        else:
            self.scan_data["iot_devices"]["other_devices"].append(device_info)
        
        self.save_scan_data()
    
    def add_exfiltration_data(self, exfiltration_data: Dict[str, Any]) -> None:
        """Agregar datos de exfiltración"""
        self.logger.info("📤 Agregando datos de exfiltración")
        
        self.scan_data["exfiltration"]["data_size"] += exfiltration_data.get('size', 0)
        self.scan_data["exfiltration"]["files_count"] += exfiltration_data.get('files_count', 0)
        
        if "sensitive_data" in exfiltration_data:
            for data in exfiltration_data["sensitive_data"]:
                data_info = {
                    "type": data.get('type', ''),
                    "location": data.get('location', ''),
                    "size": data.get('size', 0),
                    "exfiltrated_at": datetime.now().isoformat()
                }
                self.scan_data["exfiltration"]["sensitive_data"].append(data_info)
        
        self.save_scan_data()
    
    def add_server_config(self, server_data: Dict[str, Any]) -> None:
        """Agregar configuración de servidor"""
        self.logger.info(f"🖥️ Agregando servidor: {server_data.get('type', 'unknown')}")
        
        server_info = {
            "type": server_data.get('type', ''),
            "host": server_data.get('host', ''),
            "port": server_data.get('port', ''),
            "protocol": server_data.get('protocol', ''),
            "credentials": server_data.get('credentials', {}),
            "configured_at": datetime.now().isoformat()
        }
        
        server_type = server_data.get('type', '').lower()
        if 'backdoor' in server_type:
            self.scan_data["server_configs"]["backdoor_servers"].append(server_info)
        elif 'exfiltration' in server_type:
            self.scan_data["server_configs"]["exfiltration_servers"].append(server_info)
        elif 'c2' in server_type:
            self.scan_data["server_configs"]["c2_servers"].append(server_info)
        
        self.save_scan_data()
    
    def mark_phase_completed(self, phase: str) -> None:
        """Marcar fase como completada"""
        if phase not in self.scan_data["phases_completed"]:
            self.scan_data["phases_completed"].append(phase)
            self.logger.info(f"✅ Fase completada: {phase}")
            self.save_scan_data()
    
    def complete_scan(self) -> None:
        """Completar escaneo"""
        self.scan_data["metadata"]["completed_at"] = datetime.now().isoformat()
        self.scan_data["metadata"]["status"] = "completed"
        self.scan_data["timestamp"] = time.time()
        
        self.save_scan_data()
        self.logger.info("🎯 Escaneo completado")
    
    def save_scan_data(self) -> None:
        """Guardar datos del escaneo"""
        if self.scan_data_file:
            try:
                with open(self.scan_data_file, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_data, f, indent=2, ensure_ascii=False)
            except Exception as e:
                self.logger.error(f"❌ Error guardando datos del escaneo: {e}")
    
    def load_scan_data(self, mote: str) -> Optional[Dict[str, Any]]:
        """Cargar datos de un escaneo"""
        scan_dir = self.scans_dir / mote
        scan_data_file = scan_dir / "scan_data.json"
        
        if scan_data_file.exists():
            try:
                with open(scan_data_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"❌ Error cargando datos del escaneo: {e}")
        
        return None
    
    def get_all_scans(self) -> List[Dict[str, Any]]:
        """Obtener lista de todos los escaneos"""
        scans = []
        
        for scan_dir in self.scans_dir.iterdir():
            if scan_dir.is_dir():
                scan_data_file = scan_dir / "scan_data.json"
                if scan_data_file.exists():
                    try:
                        with open(scan_data_file, 'r', encoding='utf-8') as f:
                            scan_data = json.load(f)
                            scans.append(scan_data["metadata"])
                    except Exception as e:
                        self.logger.error(f"❌ Error cargando escaneo {scan_dir.name}: {e}")
        
        return sorted(scans, key=lambda x: x.get('created_at', ''), reverse=True)
    
    def get_network_discovery_data(self) -> Dict[str, Any]:
        """Obtener datos de descubrimiento de red"""
        return self.scan_data.get("network_map", {})
    
    def get_credentials_data(self) -> Dict[str, Any]:
        """Obtener datos de credenciales"""
        return self.scan_data.get("credentials", {})
    
    def get_compromised_systems_data(self) -> Dict[str, Any]:
        """Obtener datos de sistemas comprometidos"""
        return self.scan_data.get("compromised_systems", {})
    
    def get_persistence_data(self) -> Dict[str, Any]:
        """Obtener datos de persistencia"""
        return self.scan_data.get("persistence", {})
    
    def get_iot_devices_data(self) -> Dict[str, Any]:
        """Obtener datos de dispositivos IoT"""
        return self.scan_data.get("iot_devices", {})
    
    def get_connections_data(self) -> Dict[str, Any]:
        """Obtener datos de conexiones"""
        return self.scan_data.get("connections", {})
    
    def get_all_discovered_hosts(self) -> List[Dict[str, Any]]:
        """Obtener todos los hosts descubiertos"""
        hosts = []
        network_map = self.get_network_discovery_data()
        
        # Agregar IPs públicas
        hosts.extend(network_map.get("public_ips", []))
        
        # Agregar IPs privadas
        hosts.extend(network_map.get("private_ips", []))
        
        # Agregar dispositivos
        hosts.extend(network_map.get("devices", []))
        
        return hosts
    
    def get_all_credentials(self) -> List[Dict[str, Any]]:
        """Obtener todas las credenciales"""
        credentials = []
        creds_data = self.get_credentials_data()
        
        # Agregar credenciales capturadas
        credentials.extend(creds_data.get("captured_passwords", []))
        
        # Agregar credenciales por defecto
        credentials.extend(creds_data.get("default_credentials", []))
        
        # Agregar hashes crackeados
        credentials.extend(creds_data.get("cracked_hashes", []))
        
        return credentials
    
    def get_all_compromised_systems(self) -> List[Dict[str, Any]]:
        """Obtener todos los sistemas comprometidos"""
        systems = []
        compromised_data = self.get_compromised_systems_data()
        
        # Agregar sistemas de movimiento lateral
        systems.extend(compromised_data.get("lateral_movement", []))
        
        return systems
    
    def get_all_backdoors(self) -> List[Dict[str, Any]]:
        """Obtener todos los backdoors"""
        persistence_data = self.get_persistence_data()
        return persistence_data.get("backdoors", [])
    
    def get_all_iot_devices(self) -> List[Dict[str, Any]]:
        """Obtener todos los dispositivos IoT"""
        devices = []
        iot_data = self.get_iot_devices_data()
        
        # Agregar cámaras
        devices.extend(iot_data.get("cameras", []))
        
        # Agregar routers
        devices.extend(iot_data.get("routers", []))
        
        # Agregar otros dispositivos
        devices.extend(iot_data.get("other_devices", []))
        
        return devices
    
    def get_all_connections(self) -> List[Dict[str, Any]]:
        """Obtener todas las conexiones"""
        connections = []
        conn_data = self.get_connections_data()
        
        # Agregar todos los tipos de conexiones
        connections.extend(conn_data.get("ssh_access", []))
        connections.extend(conn_data.get("rdp_access", []))
        connections.extend(conn_data.get("smb_access", []))
        connections.extend(conn_data.get("database_connections", []))
        connections.extend(conn_data.get("remote_access", []))
        
        return connections
    
    def _is_public_ip(self, ip: str) -> bool:
        """Verificar si una IP es pública"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # IPs privadas
            if first == 10:
                return False
            elif first == 172 and 16 <= second <= 31:
                return False
            elif first == 192 and second == 168:
                return False
            elif first == 127:  # localhost
                return False
            
            return True
        except:
            return False
