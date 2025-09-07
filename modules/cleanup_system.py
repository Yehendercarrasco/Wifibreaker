"""
Módulo de Sistema de Limpieza Automática
Limpia backdoors, credenciales y rastros después del pentest frío
"""

import subprocess
import json
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from modules.logging_system import LoggingSystem, Colors

class CleanupSystem:
    """Sistema de limpieza automática para pentest frío"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self.logging_system = LoggingSystem(config, logger)
        
        # Resultados de limpieza
        self.cleanup_results = {
            'backdoors_removed': [],
            'credentials_removed': [],
            'persistence_removed': [],
            'files_cleaned': [],
            'services_stopped': [],
            'users_removed': [],
            'registry_cleaned': [],
            'cleanup_timestamp': time.time(),
            'cleanup_status': 'completed'
        }
    
    def cleanup_cold_pentest(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Limpiar completamente un pentest frío"""
        self.logger.info("🧊 INICIANDO LIMPIEZA DE PENTEST FRÍO")
        
        try:
            # 1. Limpiar backdoors
            self._cleanup_backdoors(scan_data)
            
            # 2. Limpiar credenciales creadas
            self._cleanup_credentials(scan_data)
            
            # 3. Limpiar persistencia
            self._cleanup_persistence(scan_data)
            
            # 4. Limpiar archivos temporales
            self._cleanup_temp_files(scan_data)
            
            # 5. Limpiar servicios
            self._cleanup_services(scan_data)
            
            # 6. Limpiar usuarios creados
            self._cleanup_users(scan_data)
            
            # 7. Limpiar registro (Windows)
            self._cleanup_registry(scan_data)
            
            # 8. Limpiar conexiones persistentes
            self._cleanup_persistent_connections(scan_data)
            
            self.logger.info("✅ LIMPIEZA DE PENTEST FRÍO COMPLETADA")
            return self.cleanup_results
            
        except Exception as e:
            self.logger.error(f"❌ Error en limpieza: {e}")
            self.cleanup_results['cleanup_status'] = 'error'
            self.cleanup_results['error'] = str(e)
            return self.cleanup_results
    
    def _cleanup_backdoors(self, scan_data: Dict[str, Any]):
        """Limpiar backdoors establecidos"""
        self.logger.info("🧹 Limpiando backdoors...")
        
        # Limpiar backdoors de persistencia
        persistence_data = scan_data.get('persistence', {})
        backdoors = persistence_data.get('backdoors', [])
        
        for backdoor in backdoors:
            try:
                self._remove_backdoor(backdoor)
                self.cleanup_results['backdoors_removed'].append({
                    'type': backdoor.get('type'),
                    'ip': backdoor.get('ip'),
                    'port': backdoor.get('port'),
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error removiendo backdoor {backdoor.get('ip')}: {e}")
        
        # Limpiar backdoors de IoT
        iot_data = scan_data.get('iot_exploitation', {})
        iot_access = iot_data.get('remote_access_established', [])
        
        for access in iot_access:
            try:
                self._remove_iot_access(access)
                self.cleanup_results['backdoors_removed'].append({
                    'type': 'iot_access',
                    'ip': access.get('ip'),
                    'device_type': access.get('device_type'),
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error removiendo acceso IoT {access.get('ip')}: {e}")
        
        # Limpiar conexiones SQL
        sql_data = scan_data.get('sql_exfiltration', {})
        sql_connections = sql_data.get('remote_connections', [])
        
        for connection in sql_connections:
            try:
                self._remove_sql_connection(connection)
                self.cleanup_results['backdoors_removed'].append({
                    'type': 'sql_connection',
                    'ip': connection.get('host'),
                    'database': connection.get('database_type'),
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error removiendo conexión SQL {connection.get('host')}: {e}")
    
    def _cleanup_credentials(self, scan_data: Dict[str, Any]):
        """Limpiar credenciales creadas"""
        self.logger.info("🧹 Limpiando credenciales...")
        
        # Limpiar usuarios creados en movimiento lateral
        lateral_data = scan_data.get('lateral_movement', {})
        compromised_systems = lateral_data.get('compromised_systems', [])
        
        for system in compromised_systems:
            if system.get('user_created'):
                try:
                    self._remove_created_user(system)
                    self.cleanup_results['credentials_removed'].append({
                        'ip': system.get('host'),
                        'username': system.get('username'),
                        'removed_at': time.time()
                    })
                except Exception as e:
                    self.logger.warning(f"⚠️ Error removiendo usuario en {system.get('host')}: {e}")
    
    def _cleanup_persistence(self, scan_data: Dict[str, Any]):
        """Limpiar persistencia establecida"""
        self.logger.info("🧹 Limpiando persistencia...")
        
        persistence_data = scan_data.get('persistence', {})
        
        # Limpiar tareas programadas
        scheduled_tasks = persistence_data.get('scheduled_tasks', [])
        for task in scheduled_tasks:
            try:
                self._remove_scheduled_task(task)
                self.cleanup_results['persistence_removed'].append({
                    'type': 'scheduled_task',
                    'name': task.get('name'),
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error removiendo tarea programada {task.get('name')}: {e}")
        
        # Limpiar servicios
        services = persistence_data.get('services', [])
        for service in services:
            try:
                self._remove_service(service)
                self.cleanup_results['services_stopped'].append({
                    'name': service.get('name'),
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error removiendo servicio {service.get('name')}: {e}")
        
        # Limpiar modificaciones de registro
        registry_mods = persistence_data.get('registry_modifications', [])
        for reg_mod in registry_mods:
            try:
                self._remove_registry_modification(reg_mod)
                self.cleanup_results['registry_cleaned'].append({
                    'key': reg_mod.get('key'),
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error limpiando registro {reg_mod.get('key')}: {e}")
    
    def _cleanup_temp_files(self, scan_data: Dict[str, Any]):
        """Limpiar archivos temporales"""
        self.logger.info("🧹 Limpiando archivos temporales...")
        
        # Limpiar archivos de evidencia (ahora en scans/)
        evidence_files = [
            "scans/reconnaissance",
            "scans/lateral_movement",
            "scans/persistence",
            "scans/iot_exploitation",
            "scans/sql_reconnaissance"
        ]
        
        for evidence_dir in evidence_files:
            try:
                evidence_path = Path(evidence_dir)
                if evidence_path.exists():
                    # Solo limpiar archivos de este escaneo específico
                    for file_path in evidence_path.glob("*.json"):
                        if self._is_scan_file(file_path, scan_data):
                            file_path.unlink()
                            self.cleanup_results['files_cleaned'].append({
                                'file': str(file_path),
                                'removed_at': time.time()
                            })
            except Exception as e:
                self.logger.warning(f"⚠️ Error limpiando evidencia {evidence_dir}: {e}")
    
    def _cleanup_services(self, scan_data: Dict[str, Any]):
        """Limpiar servicios creados"""
        self.logger.info("🧹 Limpiando servicios...")
        
        # Detener y remover servicios creados
        persistence_data = scan_data.get('persistence', {})
        services = persistence_data.get('services', [])
        
        for service in services:
            try:
                service_name = service.get('name')
                if service_name:
                    # Detener servicio
                    self._run_command(['systemctl', 'stop', service_name])
                    # Remover servicio
                    self._run_command(['systemctl', 'disable', service_name])
                    # Remover archivo de servicio
                    service_file = f"/etc/systemd/system/{service_name}.service"
                    if Path(service_file).exists():
                        Path(service_file).unlink()
                    
                    self.cleanup_results['services_stopped'].append({
                        'name': service_name,
                        'removed_at': time.time()
                    })
            except Exception as e:
                self.logger.warning(f"⚠️ Error limpiando servicio {service.get('name')}: {e}")
    
    def _cleanup_users(self, scan_data: Dict[str, Any]):
        """Limpiar usuarios creados"""
        self.logger.info("🧹 Limpiando usuarios creados...")
        
        # Remover usuarios creados en sistemas comprometidos
        lateral_data = scan_data.get('lateral_movement', {})
        compromised_systems = lateral_data.get('compromised_systems', [])
        
        for system in compromised_systems:
            if system.get('user_created'):
                try:
                    username = system.get('username')
                    if username:
                        # Remover usuario del sistema
                        self._run_command(['userdel', '-r', username])
                        self.cleanup_results['users_removed'].append({
                            'ip': system.get('host'),
                            'username': username,
                            'removed_at': time.time()
                        })
                except Exception as e:
                    self.logger.warning(f"⚠️ Error removiendo usuario {username} en {system.get('host')}: {e}")
    
    def _cleanup_registry(self, scan_data: Dict[str, Any]):
        """Limpiar modificaciones del registro (Windows)"""
        self.logger.info("🧹 Limpiando modificaciones del registro...")
        
        persistence_data = scan_data.get('persistence', {})
        registry_mods = persistence_data.get('registry_modifications', [])
        
        for reg_mod in registry_mods:
            try:
                reg_key = reg_mod.get('key')
                if reg_key:
                    # Remover clave del registro
                    self._run_command(['reg', 'delete', reg_key, '/f'])
                    self.cleanup_results['registry_cleaned'].append({
                        'key': reg_key,
                        'removed_at': time.time()
                    })
            except Exception as e:
                self.logger.warning(f"⚠️ Error limpiando registro {reg_mod.get('key')}: {e}")
    
    def _cleanup_persistent_connections(self, scan_data: Dict[str, Any]):
        """Limpiar conexiones persistentes"""
        self.logger.info("🧹 Limpiando conexiones persistentes...")
        
        persistence_data = scan_data.get('persistence', {})
        persistent_connections = persistence_data.get('persistent_connections', [])
        
        for connection in persistent_connections:
            try:
                connection_type = connection.get('type')
                if connection_type == 'ssh':
                    self._cleanup_ssh_connection(connection)
                elif connection_type == 'rdp':
                    self._cleanup_rdp_connection(connection)
                elif connection_type == 'web':
                    self._cleanup_web_connection(connection)
                
                self.cleanup_results['persistence_removed'].append({
                    'type': 'persistent_connection',
                    'connection_type': connection_type,
                    'removed_at': time.time()
                })
            except Exception as e:
                self.logger.warning(f"⚠️ Error limpiando conexión persistente: {e}")
    
    def _remove_backdoor(self, backdoor: Dict[str, Any]):
        """Remover backdoor específico"""
        backdoor_type = backdoor.get('type')
        
        if backdoor_type == 'netcat':
            # Matar proceso netcat
            self._run_command(['pkill', '-f', 'netcat'])
        elif backdoor_type == 'powershell':
            # Matar proceso PowerShell
            self._run_command(['pkill', '-f', 'powershell'])
        elif backdoor_type == 'python':
            # Matar proceso Python
            self._run_command(['pkill', '-f', 'python.*backdoor'])
    
    def _remove_iot_access(self, access: Dict[str, Any]):
        """Remover acceso IoT"""
        # Cerrar conexiones RTSP
        if access.get('device_type') == 'camera':
            self._run_command(['pkill', '-f', 'rtsp'])
    
    def _remove_sql_connection(self, connection: Dict[str, Any]):
        """Remover conexión SQL"""
        # Cerrar conexiones de base de datos
        self._run_command(['pkill', '-f', 'mysql'])
        self._run_command(['pkill', '-f', 'psql'])
        self._run_command(['pkill', '-f', 'mssql'])
    
    def _remove_created_user(self, system: Dict[str, Any]):
        """Remover usuario creado"""
        username = system.get('username')
        if username:
            # Remover usuario
            self._run_command(['userdel', '-r', username])
    
    def _remove_scheduled_task(self, task: Dict[str, Any]):
        """Remover tarea programada"""
        task_name = task.get('name')
        if task_name:
            # Remover tarea programada
            self._run_command(['crontab', '-l'], remove_line=task_name)
    
    def _remove_service(self, service: Dict[str, Any]):
        """Remover servicio"""
        service_name = service.get('name')
        if service_name:
            # Detener y deshabilitar servicio
            self._run_command(['systemctl', 'stop', service_name])
            self._run_command(['systemctl', 'disable', service_name])
            # Remover archivo de servicio
            service_file = f"/etc/systemd/system/{service_name}.service"
            if Path(service_file).exists():
                Path(service_file).unlink()
    
    def _remove_registry_modification(self, reg_mod: Dict[str, Any]):
        """Remover modificación del registro"""
        reg_key = reg_mod.get('key')
        if reg_key:
            # Remover clave del registro
            self._run_command(['reg', 'delete', reg_key, '/f'])
    
    def _cleanup_ssh_connection(self, connection: Dict[str, Any]):
        """Limpiar conexión SSH persistente"""
        # Cerrar conexiones SSH
        self._run_command(['pkill', '-f', 'ssh.*-N'])
    
    def _cleanup_rdp_connection(self, connection: Dict[str, Any]):
        """Limpiar conexión RDP persistente"""
        # Cerrar conexiones RDP
        self._run_command(['pkill', '-f', 'xfreerdp'])
    
    def _cleanup_web_connection(self, connection: Dict[str, Any]):
        """Limpiar conexión web persistente"""
        # Cerrar conexiones web
        self._run_command(['pkill', '-f', 'curl.*heartbeat'])
    
    def _is_scan_file(self, file_path: Path, scan_data: Dict[str, Any]) -> bool:
        """Verificar si el archivo pertenece al escaneo actual"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                # Verificar si contiene referencias al escaneo actual
                scan_id = scan_data.get('scan_id', '')
                return scan_id in content
        except:
            return False
    
    def _run_command(self, command: List[str], remove_line: str = None) -> Dict[str, Any]:
        """Ejecutar comando y capturar salida"""
        try:
            if remove_line and command[0] == 'crontab':
                # Manejo especial para crontab
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    filtered_lines = [line for line in lines if remove_line not in line]
                    new_crontab = '\n'.join(filtered_lines)
                    subprocess.run(['crontab', '-'], input=new_crontab, text=True)
                return {'success': True, 'stdout': '', 'stderr': ''}
            else:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr': 'Timeout'}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e)}
    
    def generate_cleanup_report(self) -> Dict[str, Any]:
        """Generar reporte de limpieza"""
        return {
            'cleanup_summary': {
                'backdoors_removed': len(self.cleanup_results['backdoors_removed']),
                'credentials_removed': len(self.cleanup_results['credentials_removed']),
                'persistence_removed': len(self.cleanup_results['persistence_removed']),
                'files_cleaned': len(self.cleanup_results['files_cleaned']),
                'services_stopped': len(self.cleanup_results['services_stopped']),
                'users_removed': len(self.cleanup_results['users_removed']),
                'registry_cleaned': len(self.cleanup_results['registry_cleaned'])
            },
            'cleanup_details': self.cleanup_results,
            'cleanup_timestamp': time.time()
        }
